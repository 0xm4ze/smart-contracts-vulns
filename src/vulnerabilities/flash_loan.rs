//! # Flash Loan Vulnerability
//!
//! Flash loan vulnerabilities occur when a smart contract doesn't properly account
//! for the possibility of atomic multi-step transactions enabled by flash loans.
//! These attacks allow malicious actors to temporarily control large amounts of assets
//! to manipulate markets, exploit pricing mechanisms, or drain funds from vulnerable contracts.
//!
//! In Rust-based smart contracts, these vulnerabilities can manifest in various ways,
//! particularly in DeFi applications across different blockchain platforms.

use crate::vulnerabilities::Vulnerability;

/// Represents a flash loan vulnerability example
pub struct FlashLoanVulnerability;

impl Vulnerability for FlashLoanVulnerability {
    fn name(&self) -> &'static str {
        "Flash Loan Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract doesn't properly account for the possibility of \
        atomic multi-step transactions enabled by flash loans. These attacks allow malicious \
        actors to temporarily control large amounts of assets to manipulate markets, \
        exploit pricing mechanisms, or drain funds from vulnerable contracts."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "All DeFi platforms"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable price calculation that can be manipulated by flash loans
        pub fn calculate_collateral_value(ctx: Context<CalculateValue>) -> Result<u64> {
            // VULNERABILITY: Using a single DEX for price discovery
            // A flash loan could be used to manipulate this price temporarily
            let token_price = ctx.accounts.dex_market.get_current_price()?;
            
            let collateral_value = ctx.accounts.user_collateral.amount * token_price;
            
            Ok(collateral_value)
        }
        
        // Vulnerable liquidation function susceptible to flash loan attacks
        pub fn liquidate_position(ctx: Context<Liquidate>) -> Result<()> {
            // Get the current value of collateral
            let collateral_token_price = ctx.accounts.token_oracle.get_price()?;
            let collateral_value = ctx.accounts.position.collateral_amount * collateral_token_price;
            
            // Check if position is undercollateralized
            let borrowed_value = ctx.accounts.position.borrowed_amount;
            
            // VULNERABILITY: Liquidation threshold can be manipulated by flash loans
            // An attacker could use a flash loan to manipulate the token price,
            // trigger liquidation, and then purchase the collateral at a discount
            if collateral_value < borrowed_value * 110 / 100 {
                // Position is undercollateralized, proceed with liquidation
                liquidate_and_distribute(ctx)?;
            } else {
                return Err(ErrorCode::PositionNotLiquidatable.into());
            }
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Examine price oracle implementations for manipulation vulnerabilities",
            "Check for single-source price dependencies",
            "Review borrowing/lending protocols for proper collateralization checks",
            "Look for time-weighted average price (TWAP) implementation",
            "Analyze liquidation mechanisms for potential abuse",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Use time-weighted average prices (TWAP) instead of spot prices",
            "Implement multiple price sources and use median or other robust aggregation",
            "Add circuit breakers for unusual price movements",
            "Consider transaction sequence analysis to detect flash loan attacks",
            "Implement rate limiting for large transactions",
        ]
    }
}

/// Example of vulnerable code susceptible to flash loan attacks
pub mod vulnerable {
    use std::collections::HashMap;
    
    #[derive(Debug, Clone)]
    pub struct LendingPool {
        pub token_reserves: u64,
        pub name: String,
    }
    
    #[derive(Debug, Clone)]
    pub struct UserPosition {
        pub owner: [u8; 32],
        pub collateral_token: String,
        pub collateral_amount: u64,
        pub borrowed_token: String,
        pub borrowed_amount: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct PriceOracle {
        pub token_prices: HashMap<String, u64>,
    }
    
    #[derive(Debug, Clone)]
    pub struct DexPool {
        pub token_a: String,
        pub token_b: String,
        pub token_a_reserves: u64,
        pub token_b_reserves: u64,
    }
    
    impl DexPool {
        pub fn get_price(&self, base_token: &str, quote_token: &str) -> u64 {
            if base_token == self.token_a && quote_token == self.token_b {
                return self.token_b_reserves * 1_000_000 / self.token_a_reserves;
            } else if base_token == self.token_b && quote_token == self.token_a {
                return self.token_a_reserves * 1_000_000 / self.token_b_reserves;
            }
            0
        }
        
        pub fn swap(&mut self, token_in: &str, amount_in: u64) -> u64 {
            let k = self.token_a_reserves * self.token_b_reserves;
            
            if token_in == self.token_a {
                let new_a_reserves = self.token_a_reserves + amount_in;
                let new_b_reserves = k / new_a_reserves;
                let amount_out = self.token_b_reserves - new_b_reserves;
                
                self.token_a_reserves = new_a_reserves;
                self.token_b_reserves = new_b_reserves;
                
                return amount_out;
            } else if token_in == self.token_b {
                let new_b_reserves = self.token_b_reserves + amount_in;
                let new_a_reserves = k / new_b_reserves;
                let amount_out = self.token_a_reserves - new_a_reserves;
                
                self.token_a_reserves = new_a_reserves;
                self.token_b_reserves = new_b_reserves;
                
                return amount_out;
            }
            
            0
        }
    }
    
    pub struct LendingProtocol {
        pub lending_pools: HashMap<String, LendingPool>,
        pub dex_pools: HashMap<String, DexPool>,
        pub positions: HashMap<u64, UserPosition>,
        pub next_position_id: u64,
        pub liquidation_threshold: u64, // e.g., 110 means 110% collateralization required
        pub liquidation_bonus: u64,     // e.g., 5 means 5% bonus for liquidators
    }
    
    impl LendingProtocol {
        pub fn new() -> Self {
            Self {
                lending_pools: HashMap::new(),
                dex_pools: HashMap::new(),
                positions: HashMap::new(),
                next_position_id: 1,
                liquidation_threshold: 110, // 110% collateralization required
                liquidation_bonus: 5,      // 5% bonus for liquidators
            }
        }
        
        /// Vulnerable flash loan function
        pub fn flash_loan(&mut self, token: &str, amount: u64, callback: impl FnOnce(&mut Self) -> Result<(), &'static str>) -> Result<(), &'static str> {
            let pool = match self.lending_pools.get_mut(token) {
                Some(pool) => pool,
                None => return Err("Pool not found"),
            };
            
            if amount > pool.token_reserves {
                return Err("Insufficient liquidity for flash loan");
            }
            
            // Lend the tokens (simulate by reducing reserves temporarily)
            pool.token_reserves -= amount;
            
            // Execute the callback (whatever the borrower wants to do with the funds)
            let result = callback(self);
            
            // Check if the pool has been repaid
            let pool = match self.lending_pools.get_mut(token) {
                Some(pool) => pool,
                None => return Err("Pool disappeared during flash loan"),
            };
            
            // VULNERABILITY: No fee for flash loans, making them free to abuse
            // Verify full repayment
            if result.is_ok() {
                if pool.token_reserves < amount {
                    return Err("Flash loan not repaid");
                }
            } else {
                // If callback failed, we need to rollback
                // (in reality this would be an atomic transaction)
                pool.token_reserves += amount;
                return result;
            }
            
            Ok(())
        }
        
        /// Vulnerable liquidation function that can be exploited using flash loans
        pub fn liquidate_position(&mut self, position_id: u64, liquidator: [u8; 32]) -> Result<(), &'static str> {
            let position = match self.positions.get(&position_id) {
                Some(position) => position.clone(),
                None => return Err("Position not found"),
            };
            
            // VULNERABILITY: Price from a single DEX pool, vulnerable to manipulation
            let collateral_price = self.get_token_price(&position.collateral_token);
            let borrowed_price = self.get_token_price(&position.borrowed_token);
            
            // Calculate position health
            let collateral_value = position.collateral_amount * collateral_price / 1_000_000;
            let debt_value = position.borrowed_amount * borrowed_price / 1_000_000;
            
            // Check if position is undercollateralized
            let min_collateral_value = debt_value * self.liquidation_threshold / 100;
            
            if collateral_value >= min_collateral_value {
                return Err("Position is not liquidatable");
            }
            
            // Calculate liquidation amount (for simplicity, we liquidate the whole position)
            let liquidation_bonus_amount = position.collateral_amount * self.liquidation_bonus / 100;
            let liquidator_collateral = position.collateral_amount - liquidation_bonus_amount;
            
            // Perform liquidation (simplified)
            // In a real contract, the liquidator would need to repay the debt
            
            // Remove the position
            self.positions.remove(&position_id);
            
            // Protocol keeps the bonus
            
            Ok(())
        }
        
        /// Helper to get token price from DEX
        fn get_token_price(&self, token: &str) -> u64 {
            // VULNERABILITY: Just using first DEX pool found for the token
            // In a real implementation, would need to find a specific pool
            for (_, pool) in &self.dex_pools {
                if pool.token_a == token {
                    return pool.get_price(token, &pool.token_b);
                } else if pool.token_b == token {
                    return pool.get_price(token, &pool.token_a);
                }
            }
            
            1_000_000 // Default price of 1.0 if not found
        }
        
        /// Create a position (for testing)
        pub fn create_position(&mut self, owner: [u8; 32], collateral_token: &str, collateral_amount: u64, borrowed_token: &str, borrowed_amount: u64) -> u64 {
            let position = UserPosition {
                owner,
                collateral_token: collateral_token.to_string(),
                collateral_amount,
                borrowed_token: borrowed_token.to_string(),
                borrowed_amount,
            };
            
            let position_id = self.next_position_id;
            self.next_position_id += 1;
            
            self.positions.insert(position_id, position);
            
            position_id
        }
    }
}

/// Example of secure code that prevents flash loan attacks
pub mod secure {
    use std::collections::HashMap;
    use std::collections::VecDeque;
    
    #[derive(Debug, Clone)]
    pub struct LendingPool {
        pub token_reserves: u64,
        pub name: String,
        pub flash_loan_fee: u64, // in basis points (e.g., 30 = 0.3%)
    }
    
    #[derive(Debug, Clone)]
    pub struct UserPosition {
        pub owner: [u8; 32],
        pub collateral_token: String,
        pub collateral_amount: u64,
        pub borrowed_token: String,
        pub borrowed_amount: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct PriceOracle {
        pub token_prices: HashMap<String, PriceData>,
        pub current_time: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct PriceData {
        pub current_price: u64,
        pub price_history: VecDeque<(u64, u64)>, // (timestamp, price)
    }
    
    impl PriceOracle {
        pub fn new() -> Self {
            Self {
                token_prices: HashMap::new(),
                current_time: 0,
            }
        }
        
        pub fn update_price(&mut self, token: &str, price: u64) {
            let price_data = self.token_prices.entry(token.to_string()).or_insert(PriceData {
                current_price: price,
                price_history: VecDeque::new(),
            });
            
            // Update current price
            price_data.current_price = price;
            
            // Add to history
            price_data.price_history.push_back((self.current_time, price));
            
            // Keep only last 24 hours
            while !price_data.price_history.is_empty() {
                let (timestamp, _) = price_data.price_history.front().unwrap();
                if self.current_time - timestamp > 86400 {
                    price_data.price_history.pop_front();
                } else {
                    break;
                }
            }
        }
        
        pub fn get_spot_price(&self, token: &str) -> Option<u64> {
            self.token_prices.get(token).map(|data| data.current_price)
        }
        
        pub fn get_twap(&self, token: &str, period: u64) -> Option<u64> {
            let price_data = self.token_prices.get(token)?;
            
            let min_time = self.current_time.saturating_sub(period);
            
            let relevant_prices: Vec<u64> = price_data.price_history
                .iter()
                .filter(|(timestamp, _)| *timestamp >= min_time)
                .map(|(_, price)| *price)
                .collect();
            
            if relevant_prices.is_empty() {
                return None;
            }
            
            let sum: u64 = relevant_prices.iter().sum();
            Some(sum / relevant_prices.len() as u64)
        }
        
        pub fn advance_time(&mut self, seconds: u64) {
            self.current_time += seconds;
        }
    }
    
    #[derive(Debug, Clone)]
    pub struct DexPool {
        pub token_a: String,
        pub token_b: String,
        pub token_a_reserves: u64,
        pub token_b_reserves: u64,
    }
    
    impl DexPool {
        pub fn get_price(&self, base_token: &str, quote_token: &str) -> u64 {
            if base_token == self.token_a && quote_token == self.token_b {
                return self.token_b_reserves * 1_000_000 / self.token_a_reserves;
            } else if base_token == self.token_b && quote_token == self.token_a {
                return self.token_a_reserves * 1_000_000 / self.token_b_reserves;
            }
            0
        }
        
        pub fn swap(&mut self, token_in: &str, amount_in: u64) -> u64 {
            let k = self.token_a_reserves * self.token_b_reserves;
            
            if token_in == self.token_a {
                let new_a_reserves = self.token_a_reserves + amount_in;
                let new_b_reserves = k / new_a_reserves;
                let amount_out = self.token_b_reserves - new_b_reserves;
                
                self.token_a_reserves = new_a_reserves;
                self.token_b_reserves = new_b_reserves;
                
                return amount_out;
            } else if token_in == self.token_b {
                let new_b_reserves = self.token_b_reserves + amount_in;
                let new_a_reserves = k / new_b_reserves;
                let amount_out = self.token_a_reserves - new_a_reserves;
                
                self.token_a_reserves = new_a_reserves;
                self.token_b_reserves = new_b_reserves;
                
                return amount_out;
            }
            
            0
        }
    }
    
    pub struct LendingProtocol {
        pub lending_pools: HashMap<String, LendingPool>,
        pub dex_pools: HashMap<String, DexPool>,
        pub positions: HashMap<u64, UserPosition>,
        pub next_position_id: u64,
        pub liquidation_threshold: u64, // e.g., 110 means 110% collateralization required
        pub liquidation_bonus: u64,     // e.g., 5 means 5% bonus for liquidators
        pub price_oracle: PriceOracle,
        pub max_flash_loan_amount: u64, // As percentage of pool size (e.g., 50 = 50%)
    }
    
    impl LendingProtocol {
        pub fn new() -> Self {
            Self {
                lending_pools: HashMap::new(),
                dex_pools: HashMap::new(),
                positions: HashMap::new(),
                next_position_id: 1,
                liquidation_threshold: 110, // 110% collateralization required
                liquidation_bonus: 5,      // 5% bonus for liquidators
                price_oracle: PriceOracle::new(),
                max_flash_loan_amount: 50, // 50% of pool can be borrowed in a flash loan
            }
        }
        
        /// Secure flash loan function with fees and limits
        pub fn flash_loan(&mut self, token: &str, amount: u64, callback: impl FnOnce(&mut Self) -> Result<(), &'static str>) -> Result<(), &'static str> {
            let pool = match self.lending_pools.get_mut(token) {
                Some(pool) => pool,
                None => return Err("Pool not found"),
            };
            
            // FIXED: Limit flash loan amount
            let max_loan = pool.token_reserves * self.max_flash_loan_amount / 100;
            if amount > max_loan {
                return Err("Flash loan exceeds maximum allowed amount");
            }
            
            // FIXED: Calculate fee
            let fee_amount = amount * pool.flash_loan_fee / 10000;
            let repay_amount = amount + fee_amount;
            
            // Record initial state for validation
            let initial_reserves = pool.token_reserves;
            
            // Lend the tokens
            pool.token_reserves -= amount;
            
            // Execute the callback
            let result = callback(self);
            
            // Check if the pool has been repaid
            let pool = match self.lending_pools.get_mut(token) {
                Some(pool) => pool,
                None => return Err("Pool disappeared during flash loan"),
            };
            
            // Verify full repayment with fee
            if result.is_ok() {
                if pool.token_reserves < initial_reserves + fee_amount {
                    return Err("Flash loan not repaid with fee");
                }
            } else {
                // If callback failed, we need to rollback
                pool.token_reserves = initial_reserves;
                return result;
            }
            
            Ok(())
        }
        
        /// Secure liquidation function resistant to flash loan attacks
        pub fn liquidate_position(&mut self, position_id: u64, liquidator: [u8; 32]) -> Result<(), &'static str> {
            let position = match self.positions.get(&position_id) {
                Some(position) => position.clone(),
                None => return Err("Position not found"),
            };
            
            // FIXED: Use TWAP from oracle instead of spot price
            let collateral_token = &position.collateral_token;
            let borrowed_token = &position.borrowed_token;
            
            // Get TWAP prices over 1 hour
            let collateral_price = match self.price_oracle.get_twap(collateral_token, 3600) {
                Some(price) => price,
                None => return Err("Insufficient price data for collateral token"),
            };
            
            let borrowed_price = match self.price_oracle.get_twap(borrowed_token, 3600) {
                Some(price) => price,
                None => return Err("Insufficient price data for borrowed token"),
            };
            
            // Calculate position health
            let collateral_value = position.collateral_amount * collateral_price / 1_000_000;
            let debt_value = position.borrowed_amount * borrowed_price / 1_000_000;
            
            // FIXED: Additional check for price deviation
            // Get spot prices to check for manipulation
            let spot_collateral_price = match self.price_oracle.get_spot_price(collateral_token) {
                Some(price) => price,
                None => return Err("No spot price for collateral token"),
            };
            
            // Check for significant deviation between TWAP and spot
            const MAX_DEVIATION_PERCENT: u64 = 10; // 10%
            let max_deviation = collateral_price * MAX_DEVIATION_PERCENT / 100;
            
            if spot_collateral_price > collateral_price && spot_collateral_price - collateral_price > max_deviation {
                return Err("Suspicious price movement detected, liquidation blocked");
            }
            
            if collateral_price > spot_collateral_price && collateral_price - spot_collateral_price > max_deviation {
                return Err("Suspicious price movement detected, liquidation blocked");
            }
            
            // Check if position is undercollateralized
            let min_collateral_value = debt_value * self.liquidation_threshold / 100;
            
            if collateral_value >= min_collateral_value {
                return Err("Position is not liquidatable");
            }
            
            // Calculate liquidation amount (for simplicity, we liquidate the whole position)
            let liquidation_bonus_amount = position.collateral_amount * self.liquidation_bonus / 100;
            let liquidator_collateral = position.collateral_amount - liquidation_bonus_amount;
            
            // Perform liquidation (simplified)
            // In a real contract, the liquidator would need to repay the debt
            
            // Remove the position
            self.positions.remove(&position_id);
            
            // Protocol keeps the bonus
            
            Ok(())
        }
        
        /// Helper to update oracle prices (for testing)
        pub fn update_oracle_price(&mut self, token: &str, price: u64) {
            self.price_oracle.update_price(token, price);
        }
        
        /// Helper to advance time in the oracle (for testing)
        pub fn advance_oracle_time(&mut self, seconds: u64) {
            self.price_oracle.advance_time(seconds);
        }
        
        /// Create a position (for testing)
        pub fn create_position(&mut self, owner: [u8; 32], collateral_token: &str, collateral_amount: u64, borrowed_token: &str, borrowed_amount: u64) -> u64 {
            let position = UserPosition {
                owner,
                collateral_token: collateral_token.to_string(),
                collateral_amount,
                borrowed_token: borrowed_token.to_string(),
                borrowed_amount,
            };
            
            let position_id = self.next_position_id;
            self.next_position_id += 1;
            
            self.positions.insert(position_id, position);
            
            position_id
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_flash_loan_attack() {
        let mut protocol = vulnerable::LendingProtocol::new();
        
        // Set up lending pools
        protocol.lending_pools.insert("USDC".to_string(), vulnerable::LendingPool {
            token_reserves: 1_000_000,
            name: "USDC Pool".to_string(),
        });
        
        // Set up a DEX pool for price manipulation
        protocol.dex_pools.insert("TOKEN_USDC".to_string(), vulnerable::DexPool {
            token_a: "TOKEN".to_string(),
            token_b: "USDC".to_string(),
            token_a_reserves: 1_000_000, // 1:1 initial price
            token_b_reserves: 1_000_000,
        });
        
        // Create a position that's well-collateralized at current prices
        let user = [1u8; 32];
        let position_id = protocol.create_position(user, "TOKEN", 100_000, "USDC", 80_000);
        
        // Verify position is not liquidatable initially
        let attacker = [2u8; 32];
        let result = protocol.liquidate_position(position_id, attacker);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Position is not liquidatable");
        
        // Simulate a flash loan attack
        let result = protocol.flash_loan("USDC", 900_000, |protocol| {
            // Use the flash-loaned USDC to manipulate the TOKEN price in the DEX
            let dex = protocol.dex_pools.get_mut("TOKEN_USDC").unwrap();
            
            // Manipulate price by doing a large swap
            dex.swap("USDC", 900_000);
            
            // Now try to liquidate the position when price is manipulated
            let _ = protocol.liquidate_position(position_id, attacker);
            
            // Swap back to repay the flash loan
            dex.swap("TOKEN", 900_000);
            
            Ok(())
        });
        
        // The attack succeeded and the position is now liquidated
        assert!(result.is_ok());
        assert!(!protocol.positions.contains_key(&position_id));
    }
    
    #[test]
    fn test_secure_flash_loan_protection() {
        let mut protocol = secure::LendingProtocol::new();
        
        // Set up lending pools with fees
        protocol.lending_pools.insert("USDC".to_string(), secure::LendingPool {
            token_reserves: 1_000_000,
            name: "USDC Pool".to_string(),
            flash_loan_fee: 30, // 0.3% fee
        });
        
        // Set up a DEX pool for price discovery
        protocol.dex_pools.insert("TOKEN_USDC".to_string(), secure::DexPool {
            token_a: "TOKEN".to_string(),
            token_b: "USDC".to_string(),
            token_a_reserves: 1_000_000, // 1:1 initial price
            token_b_reserves: 1_000_000,
        });
        
        // Seed the oracle with historical prices
        for i in 0..24 {
            protocol.update_oracle_price("TOKEN", 1_000_000); // Price of 1.0
            protocol.update_oracle_price("USDC", 1_000_000);  // Price of 1.0
            protocol.advance_oracle_time(3600); // Advance 1 hour
        }
        
        // Create a position that's well-collateralized at current prices
        let user = [1u8; 32];
        let position_id = protocol.create_position(user, "TOKEN", 100_000, "USDC", 80_000);
        
        // Verify position is not liquidatable initially
        let attacker = [2u8; 32];
        let result = protocol.liquidate_position(position_id, attacker);
        assert!(result.is_err());
        
        // Simulate a flash loan attack attempt
        let result = protocol.flash_loan("USDC", 900_000, |protocol| {
            // Use the flash-loaned USDC to manipulate the TOKEN price in the DEX
            let dex = protocol.dex_pools.get_mut("TOKEN_USDC").unwrap();
            
            // Manipulate price by doing a large swap
            dex.swap("USDC", 900_000);
            
            // Update the oracle's spot price
            protocol.update_oracle_price("TOKEN", 500_000); // Price drops to 0.5
            
            // Try to liquidate the position when price is manipulated
            let liquidation_result = protocol.liquidate_position(position_id, attacker);
            
            // This will fail because TWAP is still at 1.0
            assert!(liquidation_result.is_err());
            
            // Swap back to repay the flash loan with fee
            let usdc_needed = 900_000 + (900_000 * 30 / 10000);
            dex.swap("TOKEN", usdc_needed);
            
            Ok(())
        });
        
        // The attack was prevented by TWAP
        assert!(result.is_ok());
        assert!(protocol.positions.contains_key(&position_id)); // Position still exists
    }
}
