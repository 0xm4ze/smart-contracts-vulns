//! # Oracle Manipulation Vulnerability
//!
//! Oracle manipulation vulnerabilities occur when a smart contract relies on external
//! data sources (oracles) that can be manipulated or tampered with, leading to
//! incorrect contract behavior, price manipulation, or other exploitative scenarios.
//!
//! This is particularly important in DeFi applications on any blockchain platform.

use crate::vulnerabilities::Vulnerability;

/// Represents an oracle manipulation vulnerability example
pub struct OracleManipulationVulnerability;

impl Vulnerability for OracleManipulationVulnerability {
    fn name(&self) -> &'static str {
        "Oracle Manipulation Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract relies on external data sources (oracles) \
        that can be manipulated, leading to incorrect contract behavior, \
        price manipulation, or other exploitative scenarios."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All DeFi platforms"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function that relies on a single oracle
        pub fn liquidate_position(ctx: Context<Liquidate>) -> Result<()> {
            // VULNERABILITY: Single oracle used for critical price data
            let token_price = ctx.accounts.price_oracle.get_price()?;
            
            let collateral_value = ctx.accounts.user_position.collateral_amount * token_price;
            let loan_value = ctx.accounts.user_position.loan_amount;
            
            // If collateral value falls below threshold, liquidate
            if collateral_value < loan_value * 110 / 100 {
                // Liquidation logic...
                liquidate_user_position(ctx)?;
            } else {
                return Err(ErrorCode::CannotLiquidate.into());
            }
            
            Ok(())
        }
        
        // Vulnerable function with time-based vulnerability
        pub fn settle_options(ctx: Context<SettleOptions>) -> Result<()> {
            // VULNERABILITY: Uses the latest price without considering manipulation
            // An attacker could manipulate the price right before expiration
            let settlement_price = ctx.accounts.price_oracle.get_current_price()?;
            
            // Settle all options based on this price
            for option in ctx.accounts.option_positions.iter() {
                settle_option(option, settlement_price)?;
            }
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Check if the contract relies on a single oracle for critical price data",
            "Examine if there are time-weighted average price (TWAP) mechanisms",
            "Verify if the contract has mechanisms to detect abnormal price movements",
            "Look for flash loan attack vectors related to price oracles",
            "Check for oracle freshness verification (staleness checks)",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Use multiple independent oracles and aggregate their values (e.g., median)",
            "Implement time-weighted average prices (TWAP) to prevent manipulation",
            "Add price deviation checks to detect abnormal movements",
            "Include freshness checks to ensure oracle data is recent",
            "Consider using decentralized oracles like Chainlink where available",
        ]
    }
}

/// Example of vulnerable code susceptible to oracle manipulation
pub mod vulnerable {
    #[derive(Debug, Clone)]
    pub struct PriceOracle {
        pub latest_price: u64,
        pub last_update_time: u64,
    }
    
    impl PriceOracle {
        pub fn new(initial_price: u64) -> Self {
            Self {
                latest_price: initial_price,
                last_update_time: 0,
            }
        }
        
        pub fn get_price(&self) -> u64 {
            // Simply returns the latest price without any checks
            self.latest_price
        }
        
        pub fn update_price(&mut self, new_price: u64, timestamp: u64) {
            self.latest_price = new_price;
            self.last_update_time = timestamp;
        }
    }
    
    #[derive(Debug, Clone)]
    pub struct LendingPosition {
        pub owner: [u8; 32],
        pub collateral_amount: u64,
        pub loan_amount: u64,
    }
    
    pub struct LendingProtocol {
        pub oracle: PriceOracle,
        pub positions: std::collections::HashMap<[u8; 32], LendingPosition>,
        pub current_time: u64,
    }
    
    impl LendingProtocol {
        pub fn new(initial_price: u64) -> Self {
            Self {
                oracle: PriceOracle::new(initial_price),
                positions: std::collections::HashMap::new(),
                current_time: 0,
            }
        }
        
        /// Vulnerable function that can be manipulated by oracle price
        pub fn liquidate_position(&mut self, position_id: [u8; 32]) -> Result<(), &'static str> {
            let position = match self.positions.get(&position_id) {
                Some(position) => position,
                None => return Err("Position not found"),
            };
            
            // VULNERABILITY: Single price source without checks
            let token_price = self.oracle.get_price();
            
            let collateral_value = position.collateral_amount * token_price;
            let loan_value = position.loan_amount;
            
            // If collateral value falls below threshold, liquidate
            if collateral_value < loan_value * 110 / 100 {
                // Liquidation logic
                self.positions.remove(&position_id);
                return Ok(());
            } else {
                return Err("Position is not eligible for liquidation");
            }
        }
        
        /// Function to update the oracle price (for testing)
        pub fn update_oracle_price(&mut self, new_price: u64) {
            self.current_time += 1;
            self.oracle.update_price(new_price, self.current_time);
        }
    }
}

/// Example of secure code that prevents oracle manipulation
pub mod secure {
    #[derive(Debug, Clone)]
    pub struct PriceOracle {
        pub latest_price: u64,
        pub historical_prices: Vec<(u64, u64)>, // (timestamp, price)
        pub last_update_time: u64,
    }
    
    impl PriceOracle {
        pub fn new(initial_price: u64) -> Self {
            Self {
                latest_price: initial_price,
                historical_prices: vec![(0, initial_price)],
                last_update_time: 0,
            }
        }
        
        /// Get current price with staleness check
        pub fn get_price(&self, current_time: u64) -> Result<u64, &'static str> {
            // FIXED: Check if the price data is stale
            const MAX_AGE: u64 = 300; // 5 minutes
            
            if current_time - self.last_update_time > MAX_AGE {
                return Err("Oracle data is stale");
            }
            
            Ok(self.latest_price)
        }
        
        /// Get TWAP (Time-Weighted Average Price)
        pub fn get_twap(&self, period: u64, current_time: u64) -> Result<u64, &'static str> {
            // FIXED: Get time-weighted average price over a period
            let min_time = current_time.saturating_sub(period);
            
            let relevant_prices: Vec<(u64, u64)> = self
                .historical_prices
                .iter()
                .filter(|&&(timestamp, _)| timestamp >= min_time)
                .cloned()
                .collect();
            
            if relevant_prices.is_empty() {
                return Err("Insufficient historical price data");
            }
            
            // Simplified TWAP calculation
            let sum: u64 = relevant_prices.iter().map(|&(_, price)| price).sum();
            Ok(sum / relevant_prices.len() as u64)
        }
        
        pub fn update_price(&mut self, new_price: u64, timestamp: u64) {
            // FIXED: Check for extreme price movements
            const MAX_PRICE_CHANGE_PERCENTAGE: u64 = 20; // 20%
            
            if !self.historical_prices.is_empty() {
                let last_price = self.historical_prices.last().unwrap().1;
                
                // Calculate percentage change
                let change = if new_price > last_price {
                    (new_price - last_price) * 100 / last_price
                } else {
                    (last_price - new_price) * 100 / last_price
                };
                
                // If change is too extreme, dampen it
                if change > MAX_PRICE_CHANGE_PERCENTAGE {
                    let max_change = last_price * MAX_PRICE_CHANGE_PERCENTAGE / 100;
                    if new_price > last_price {
                        self.latest_price = last_price + max_change;
                    } else {
                        self.latest_price = last_price.saturating_sub(max_change);
                    }
                } else {
                    self.latest_price = new_price;
                }
            } else {
                self.latest_price = new_price;
            }
            
            self.historical_prices.push((timestamp, self.latest_price));
            self.last_update_time = timestamp;
            
            // Keep only recent history (e.g., last 24 hours)
            const HISTORY_RETENTION: u64 = 86400; // 24 hours
            let min_time = timestamp.saturating_sub(HISTORY_RETENTION);
            self.historical_prices.retain(|&(ts, _)| ts >= min_time);
        }
    }
    
    #[derive(Debug, Clone)]
    pub struct LendingPosition {
        pub owner: [u8; 32],
        pub collateral_amount: u64,
        pub loan_amount: u64,
    }
    
    pub struct LendingProtocol {
        pub primary_oracle: PriceOracle,
        pub backup_oracle: PriceOracle,
        pub positions: std::collections::HashMap<[u8; 32], LendingPosition>,
        pub current_time: u64,
    }
    
    impl LendingProtocol {
        pub fn new(initial_price: u64) -> Self {
            Self {
                primary_oracle: PriceOracle::new(initial_price),
                backup_oracle: PriceOracle::new(initial_price),
                positions: std::collections::HashMap::new(),
                current_time: 0,
            }
        }
        
        /// Secure function that prevents oracle manipulation
        pub fn liquidate_position(&mut self, position_id: [u8; 32]) -> Result<(), &'static str> {
            let position = match self.positions.get(&position_id) {
                Some(position) => position,
                None => return Err("Position not found"),
            };
            
            // FIXED: Use multiple sources and TWAP
            
            // Get primary oracle price with staleness check
            let primary_price = match self.primary_oracle.get_price(self.current_time) {
                Ok(price) => price,
                Err(_) => {
                    // Fallback to backup oracle if primary is stale
                    match self.backup_oracle.get_price(self.current_time) {
                        Ok(price) => price,
                        Err(_) => return Err("All oracle data is stale"),
                    }
                }
            };
            
            // Get TWAP for more stability
            const TWAP_PERIOD: u64 = 3600; // 1 hour
            let twap_price = self.primary_oracle.get_twap(TWAP_PERIOD, self.current_time)
                .unwrap_or(primary_price); // Fallback to spot price if TWAP fails
            
            // Use the more conservative price (lower price is worse for the borrower)
            let token_price = std::cmp::min(primary_price, twap_price);
            
            let collateral_value = position.collateral_amount * token_price;
            let loan_value = position.loan_amount;
            
            // If collateral value falls below threshold, liquidate
            if collateral_value < loan_value * 110 / 100 {
                // Liquidation logic
                self.positions.remove(&position_id);
                return Ok(());
            } else {
                return Err("Position is not eligible for liquidation");
            }
        }
        
        /// Functions to update oracle prices (for testing)
        pub fn update_primary_oracle_price(&mut self, new_price: u64) {
            self.current_time += 1;
            self.primary_oracle.update_price(new_price, self.current_time);
        }
        
        pub fn update_backup_oracle_price(&mut self, new_price: u64) {
            self.current_time += 1;
            self.backup_oracle.update_price(new_price, self.current_time);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_oracle_manipulation() {
        let mut protocol = vulnerable::LendingProtocol::new(100); // Initial price: 100
        let position_id = [1u8; 32];
        
        // Create a position with 200 collateral and 100 loan
        // At price 100, the collateral value is 20,000 which is well above the required 110%
        protocol.positions.insert(position_id, vulnerable::LendingPosition {
            owner: position_id,
            collateral_amount: 200,
            loan_amount: 100,
        });
        
        // Cannot liquidate at the current price
        let result = protocol.liquidate_position(position_id);
        assert!(result.is_err());
        
        // An attacker manipulates the oracle price drastically
        protocol.update_oracle_price(45); // Drop price by 55%
        
        // Now the position can be liquidated
        let result = protocol.liquidate_position(position_id);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_secure_oracle_manipulation_prevention() {
        let mut protocol = secure::LendingProtocol::new(100);
        let position_id = [1u8; 32];
        
        // Create a position with 200 collateral and 100 loan
        protocol.positions.insert(position_id, secure::LendingPosition {
            owner: position_id,
            collateral_amount: 200,
            loan_amount: 100,
        });
        
        // Try to manipulate the price with a large drop
        protocol.update_primary_oracle_price(45);
        
        // Cannot liquidate because the price change was too extreme and was dampened
        // Also, the TWAP will take into account the previous prices
        let result = protocol.liquidate_position(position_id);
        assert!(result.is_err());
        
        // Even with a sustained attack over multiple blocks, the dampening
        // and TWAP mechanisms make it much harder to manipulate the price
        for _ in 0..5 {
            protocol.update_primary_oracle_price(45);
        }
        
        // It would take much longer to drop the price enough for liquidation
        let result = protocol.liquidate_position(position_id);
        assert!(result.is_err());
    }
}
