//! # Illicit Fee Collection Vulnerability
//!
//! Illicit fee collection vulnerabilities occur when a smart contract allows
//! unauthorized or excessive fees to be extracted from users, either through
//! direct manipulation of fee parameters or through more subtle mechanisms
//! that redirect value to unintended recipients.
//!
//! These vulnerabilities can exist in various forms, from fee parameters that
//! can be manipulated to outright theft of funds.

use crate::vulnerabilities::Vulnerability;

/// Represents an illicit fee collection vulnerability example
pub struct IllicitFeeVulnerability;

impl Vulnerability for IllicitFeeVulnerability {
    fn name(&self) -> &'static str {
        "Illicit Fee Collection Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract allows unauthorized or excessive fees to be \
        extracted from users, either through direct manipulation of fee parameters \
        or through more subtle mechanisms that redirect value to unintended recipients."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All DeFi platforms"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function with manipulable fee destination
        pub fn swap_tokens(ctx: Context<SwapTokens>, amount_in: u64) -> Result<()> {
            // Calculate the output amount
            let fee_percentage = ctx.accounts.pool.fee_percentage;
            let fee_amount = amount_in * fee_percentage / 10000; // Fee in basis points
            
            // VULNERABILITY: The fee recipient can be changed by anyone
            // or is not properly validated against an authorized recipient
            let amount_out = calculate_swap_amount(amount_in - fee_amount);
            
            // Transfer tokens
            transfer_tokens_from(ctx.accounts.user, ctx.accounts.pool, amount_in)?;
            transfer_tokens_to(ctx.accounts.pool, ctx.accounts.user, amount_out)?;
            
            // Send fee to fee collector
            // VULNERABILITY: No validation of fee_collector account
            transfer_tokens_to(ctx.accounts.pool, ctx.accounts.fee_collector, fee_amount)?;
            
            Ok(())
        }
        
        // Vulnerable function with hidden fee
        pub fn provide_liquidity(ctx: Context<ProvideLiquidity>, amount_a: u64, amount_b: u64) -> Result<()> {
            // VULNERABILITY: Hidden fee taken from the provided liquidity
            let actual_amount_a = amount_a * 9950 / 10000; // Hidden 0.5% fee
            let actual_amount_b = amount_b * 9950 / 10000; // Hidden 0.5% fee
            
            // The hidden fee is silently kept in the contract or sent elsewhere
            let fee_a = amount_a - actual_amount_a;
            let fee_b = amount_b - actual_amount_b;
            
            // Process the liquidity provision with the reduced amounts
            // but user thinks they're getting LP tokens for the full amount
            process_liquidity_provision(ctx, actual_amount_a, actual_amount_b)?;
            
            // Hidden fee transfer
            transfer_tokens_to(ctx.accounts.pool, ctx.accounts.hidden_fee_collector, fee_a)?;
            transfer_tokens_to(ctx.accounts.pool, ctx.accounts.hidden_fee_collector, fee_b)?;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Examine fee calculation logic for manipulation opportunities",
            "Check validation of fee recipient addresses",
            "Compare documented fees with actual implementation",
            "Trace token flows to identify potential fee leakage",
            "Look for fee parameters that can be changed without proper authorization",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Implement strict validation of fee recipients",
            "Use access control for fee parameter changes",
            "Document all fees transparently in code and user interfaces",
            "Implement time-locks for fee parameter changes",
            "Use multi-signature or DAO governance for fee-related changes",
        ]
    }
}

/// Example of vulnerable code with illicit fee collection issues
pub mod vulnerable {
    #[derive(Debug, Clone)]
    pub struct LiquidityPool {
        pub token_a_reserves: u64,
        pub token_b_reserves: u64,
        pub fee_percentage: u64,          // In basis points (1/100 of 1%)
        pub fee_recipient: [u8; 32],
        pub total_supply: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct UserAccount {
        pub owner: [u8; 32],
        pub token_a_balance: u64,
        pub token_b_balance: u64,
        pub lp_tokens: u64,
    }
    
    pub struct DexProtocol {
        pub admin: [u8; 32],
        pub pools: std::collections::HashMap<u64, LiquidityPool>,
        pub users: std::collections::HashMap<[u8; 32], UserAccount>,
    }
    
    impl DexProtocol {
        pub fn new(admin: [u8; 32]) -> Self {
            Self {
                admin,
                pools: std::collections::HashMap::new(),
                users: std::collections::HashMap::new(),
            }
        }
        
        /// Vulnerable function with manipulable fee recipient
        pub fn set_fee_recipient(&mut self, pool_id: u64, new_recipient: [u8; 32]) -> Result<(), &'static str> {
            let pool = match self.pools.get_mut(&pool_id) {
                Some(pool) => pool,
                None => return Err("Pool not found"),
            };
            
            // VULNERABILITY: No access control on fee recipient changes
            // Anyone can change the fee recipient to any address
            pool.fee_recipient = new_recipient;
            
            Ok(())
        }
        
        /// Vulnerable function with fee parameter manipulation
        pub fn set_fee_percentage(&mut self, pool_id: u64, new_fee: u64) -> Result<(), &'static str> {
            let pool = match self.pools.get_mut(&pool_id) {
                Some(pool) => pool,
                None => return Err("Pool not found"),
            };
            
            // VULNERABILITY: Weak bounds checking allows excessive fees
            // Max fee of 50% (5000 basis points) is extremely high
            if new_fee > 5000 {
                return Err("Fee too high (max 50%)");
            }
            
            pool.fee_percentage = new_fee;
            
            Ok(())
        }
        
        /// Vulnerable swap function with hidden fees
        pub fn swap(&mut self, user_id: [u8; 32], pool_id: u64, token_a_amount: u64) -> Result<u64, &'static str> {
            let user = match self.users.get_mut(&user_id) {
                Some(user) => user,
                None => return Err("User not found"),
            };
            
            let pool = match self.pools.get_mut(&pool_id) {
                Some(pool) => pool,
                None => return Err("Pool not found"),
            };
            
            // Check user balance
            if user.token_a_balance < token_a_amount {
                return Err("Insufficient token A balance");
            }
            
            // Calculate swap amount using constant product formula (A * B = k)
            let k = pool.token_a_reserves * pool.token_b_reserves;
            
            // Apply the documented fee
            let fee_amount = token_a_amount * pool.fee_percentage / 10000;
            let amount_after_fee = token_a_amount - fee_amount;
            
            // Calculate output amount
            let new_token_a_reserves = pool.token_a_reserves + amount_after_fee;
            let new_token_b_reserves = k / new_token_a_reserves;
            let token_b_out = pool.token_b_reserves - new_token_b_reserves;
            
            // VULNERABILITY: Hidden additional fee not disclosed to users
            // This reduces the actual output amount by another 0.5%
            let hidden_fee = token_b_out * 50 / 10000; // 0.5% hidden fee
            let actual_token_b_out = token_b_out - hidden_fee;
            
            // Update balances
            user.token_a_balance -= token_a_amount;
            user.token_b_balance += actual_token_b_out;
            
            // Update pool reserves
            pool.token_a_reserves = new_token_a_reserves + fee_amount;
            pool.token_b_reserves = new_token_b_reserves;
            
            // VULNERABILITY: The hidden fee is kept in the pool rather than
            // being properly accounted for, effectively stealing from liquidity providers
            
            Ok(actual_token_b_out)
        }
    }
}

/// Example of secure code that prevents illicit fee collection
pub mod secure {
    #[derive(Debug, Clone)]
    pub struct LiquidityPool {
        pub token_a_reserves: u64,
        pub token_b_reserves: u64,
        pub fee_percentage: u64,          // In basis points (1/100 of 1%)
        pub fee_recipient: [u8; 32],
        pub total_supply: u64,
        pub protocol_fee_percentage: u64, // Separate protocol fee (transparent)
    }
    
    #[derive(Debug, Clone)]
    pub struct UserAccount {
        pub owner: [u8; 32],
        pub token_a_balance: u64,
        pub token_b_balance: u64,
        pub lp_tokens: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct FeeChange {
        pub pool_id: u64,
        pub new_fee: u64,
        pub timestamp: u64,
        pub effective_time: u64,
    }
    
    pub struct DexProtocol {
        pub admin: [u8; 32],
        pub fee_admin: [u8; 32],
        pub pools: std::collections::HashMap<u64, LiquidityPool>,
        pub users: std::collections::HashMap<[u8; 32], UserAccount>,
        pub pending_fee_changes: Vec<FeeChange>,
        pub current_time: u64,
    }
    
    impl DexProtocol {
        pub fn new(admin: [u8; 32]) -> Self {
            Self {
                admin,
                fee_admin: admin, // Initially the same, can be changed
                pools: std::collections::HashMap::new(),
                users: std::collections::HashMap::new(),
                pending_fee_changes: Vec::new(),
                current_time: 0,
            }
        }
        
        /// Secure function with proper access control for fee recipient
        pub fn set_fee_recipient(&mut self, caller: [u8; 32], pool_id: u64, new_recipient: [u8; 32]) -> Result<(), &'static str> {
            // FIXED: Proper access control check
            if caller != self.fee_admin {
                return Err("Only fee admin can change fee recipient");
            }
            
            let pool = match self.pools.get_mut(&pool_id) {
                Some(pool) => pool,
                None => return Err("Pool not found"),
            };
            
            pool.fee_recipient = new_recipient;
            
            Ok(())
        }
        
        /// Secure function with timelock for fee changes
        pub fn propose_fee_change(&mut self, caller: [u8; 32], pool_id: u64, new_fee: u64) -> Result<(), &'static str> {
            // FIXED: Proper access control
            if caller != self.fee_admin {
                return Err("Only fee admin can propose fee changes");
            }
            
            // FIXED: Stricter bounds checking
            // Max fee of 1% (100 basis points) is more reasonable
            if new_fee > 100 {
                return Err("Fee too high (max 1%)");
            }
            
            // Ensure pool exists
            if !self.pools.contains_key(&pool_id) {
                return Err("Pool not found");
            }
            
            // Create timelock for change (24 hours)
            let change = FeeChange {
                pool_id,
                new_fee,
                timestamp: self.current_time,
                effective_time: self.current_time + 86400, // 24 hours later
            };
            
            self.pending_fee_changes.push(change);
            
            Ok(())
        }
        
        /// Apply pending fee changes that have passed their timelock
        pub fn apply_pending_fee_changes(&mut self) -> Result<usize, &'static str> {
            let mut applied_count = 0;
            
            // Find changes that can be applied
            let pending_changes: Vec<FeeChange> = self.pending_fee_changes
                .iter()
                .filter(|c| c.effective_time <= self.current_time)
                .cloned()
                .collect();
            
            // Apply each change
            for change in pending_changes {
                if let Some(pool) = self.pools.get_mut(&change.pool_id) {
                    pool.fee_percentage = change.new_fee;
                    applied_count += 1;
                }
            }
            
            // Remove applied changes
            self.pending_fee_changes.retain(|c| c.effective_time > self.current_time);
            
            Ok(applied_count)
        }
        
        /// Secure swap function with transparent fees
        pub fn swap(&mut self, user_id: [u8; 32], pool_id: u64, token_a_amount: u64) -> Result<u64, &'static str> {
            let user = match self.users.get_mut(&user_id) {
                Some(user) => user,
                None => return Err("User not found"),
            };
            
            let pool = match self.pools.get_mut(&pool_id) {
                Some(pool) => pool,
                None => return Err("Pool not found"),
            };
            
            // Check user balance
            if user.token_a_balance < token_a_amount {
                return Err("Insufficient token A balance");
            }
            
            // Calculate swap amount using constant product formula (A * B = k)
            let k = pool.token_a_reserves * pool.token_b_reserves;
            
            // FIXED: Transparent fee calculation
            let lp_fee_amount = token_a_amount * pool.fee_percentage / 10000;
            let protocol_fee_amount = token_a_amount * pool.protocol_fee_percentage / 10000;
            let total_fee = lp_fee_amount + protocol_fee_amount;
            
            // Apply fees
            let amount_after_fee = token_a_amount - total_fee;
            
            // Calculate output amount
            let new_token_a_reserves = pool.token_a_reserves + amount_after_fee;
            let new_token_b_reserves = k / new_token_a_reserves;
            let token_b_out = pool.token_b_reserves - new_token_b_reserves;
            
            // FIXED: No hidden fees, what you see is what you get
            
            // Update balances
            user.token_a_balance -= token_a_amount;
            user.token_b_balance += token_b_out;
            
            // Update pool reserves
            // LP fee stays in the pool, benefiting all LPs
            pool.token_a_reserves = new_token_a_reserves + lp_fee_amount;
            pool.token_b_reserves = new_token_b_reserves;
            
            // Send protocol fee to designated recipient
            if protocol_fee_amount > 0 {
                let fee_recipient = self.users.entry(pool.fee_recipient).or_insert(UserAccount {
                    owner: pool.fee_recipient,
                    token_a_balance: 0,
                    token_b_balance: 0,
                    lp_tokens: 0,
                });
                
                fee_recipient.token_a_balance += protocol_fee_amount;
            }
            
            Ok(token_b_out)
        }
        
        /// Helper to advance time (for testing)
        pub fn advance_time(&mut self, seconds: u64) {
            self.current_time += seconds;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_fee_manipulation() {
        let mut dex = vulnerable::DexProtocol::new([1u8; 32]);
        let user = [2u8; 32];
        let attacker = [3u8; 32];
        let pool_id = 1;
        
        // Create pool with 0.3% fee
        dex.pools.insert(pool_id, vulnerable::LiquidityPool {
            token_a_reserves: 1_000_000,
            token_b_reserves: 1_000_000,
            fee_percentage: 30, // 0.3%
            fee_recipient: [1u8; 32], // Admin
            total_supply: 1_000_000,
        });
        
        // Create user account
        dex.users.insert(user, vulnerable::UserAccount {
            owner: user,
            token_a_balance: 10_000,
            token_b_balance: 10_000,
            lp_tokens: 0,
        });
        
        // Attacker can redirect fees to themselves
        let result = dex.set_fee_recipient(pool_id, attacker);
        assert!(result.is_ok());
        
        // Attacker can drastically increase fees
        let result = dex.set_fee_percentage(pool_id, 5000); // 50% fee!
        assert!(result.is_ok());
        
        // Verify the changes were applied
        let pool = dex.pools.get(&pool_id).unwrap();
        assert_eq!(pool.fee_percentage, 5000);
        assert_eq!(pool.fee_recipient, attacker);
    }
    
    #[test]
    fn test_secure_fee_protection() {
        let mut dex = secure::DexProtocol::new([1u8; 32]);
        let user = [2u8; 32];
        let attacker = [3u8; 32];
        let pool_id = 1;
        
        // Create pool with standard fees
        dex.pools.insert(pool_id, secure::LiquidityPool {
            token_a_reserves: 1_000_000,
            token_b_reserves: 1_000_000,
            fee_percentage: 30, // 0.3%
            fee_recipient: [1u8; 32], // Admin
            total_supply: 1_000_000,
            protocol_fee_percentage: 5, // 0.05% protocol fee
        });
        
        // Create user account
        dex.users.insert(user, secure::UserAccount {
            owner: user,
            token_a_balance: 10_000,
            token_b_balance: 10_000,
            lp_tokens: 0,
        });
        
        // Attacker cannot change fee recipient
        let result = dex.set_fee_recipient(attacker, pool_id, attacker);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Only fee admin can change fee recipient");
        
        // Admin can propose a fee change, but it's timelocked
        let result = dex.propose_fee_change(dex.fee_admin, pool_id, 40); // 0.4%
        assert!(result.is_ok());
        
        // Admin cannot set excessive fees
        let result = dex.propose_fee_change(dex.fee_admin, pool_id, 200); // 2%
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Fee too high (max 1%)");
        
        // Fee change not applied until timelock expires
        let result = dex.apply_pending_fee_changes();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // No changes applied yet
        
        // Advance time past the timelock
        dex.advance_time(90000); // 25 hours
        
        // Now the fee change can be applied
        let result = dex.apply_pending_fee_changes();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // 1 change applied
        
        // Verify the fee was changed
        let pool = dex.pools.get(&pool_id).unwrap();
        assert_eq!(pool.fee_percentage, 40); // Updated to 0.4%
        assert_eq!(pool.fee_recipient, [1u8; 32]); // Still the admin
    }
}
