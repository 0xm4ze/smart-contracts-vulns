//! # Integer Overflow/Underflow Vulnerability
//!
//! Integer overflow/underflow vulnerabilities occur when arithmetic operations
//! produce results that exceed the range of the data type, potentially leading to
//! unexpected behavior, including bypassing validation checks or manipulating balances.
//!
//! While Rust provides some built-in protection in debug mode, these protections
//! might be disabled in release builds, leading to potential vulnerabilities.

use crate::vulnerabilities::Vulnerability;

/// Represents an integer overflow/underflow vulnerability example
pub struct OverflowVulnerability;

impl Vulnerability for OverflowVulnerability {
    fn name(&self) -> &'static str {
        "Integer Overflow/Underflow Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when arithmetic operations exceed the range of the data type, \
        potentially leading to unexpected behavior. While Rust provides some \
        built-in protection in debug mode, these might be disabled in release builds."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All Rust-based contracts"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function that doesn't check for overflow
        pub fn add_to_balance(ctx: Context<UpdateBalance>, amount: u64) -> Result<()> {
            // VULNERABILITY: No overflow check
            // If account.balance is close to u64::MAX, this will overflow
            ctx.accounts.user_account.balance += amount;
            
            Ok(())
        }
        
        // Vulnerable function with indirect overflow
        pub fn process_large_transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
            // VULNERABILITY: If amount + fee overflows, this check might be bypassed
            let fee = amount / 100; // 1% fee
            
            if amount + fee > ctx.accounts.payer.balance {
                return Err(ErrorCode::InsufficientFunds.into());
            }
            
            // Execution continues with insufficient balance
            ctx.accounts.payer.balance -= amount + fee;
            ctx.accounts.receiver.balance += amount;
            ctx.accounts.fee_collector.balance += fee;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Check arithmetic operations that could potentially overflow/underflow",
            "Look for unchecked arithmetic, especially with user-supplied inputs",
            "Verify that bounds checking is performed before critical operations",
            "Check if the code uses checked arithmetic functions",
            "Examine build configurations to ensure overflow checks aren't disabled in production",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Use checked arithmetic operations (checked_add, checked_mul, etc.)",
            "Implement explicit bounds checking before performing arithmetic",
            "Consider using the num-traits crate for more robust handling",
            "Use the Saturating trait for operations that should saturate rather than overflow",
            "Keep panic-on-overflow enabled in release builds for critical code paths",
        ]
    }
}

/// Example of vulnerable code susceptible to overflow/underflow
pub mod vulnerable {
    pub struct TokenAccount {
        pub balance: u64,
    }
    
    pub struct TokenProgram {
        pub accounts: std::collections::HashMap<[u8; 32], TokenAccount>,
    }
    
    impl TokenProgram {
        pub fn new() -> Self {
            Self {
                accounts: std::collections::HashMap::new(),
            }
        }
        
        /// Vulnerable function that doesn't check for overflow
        pub fn add_tokens(&mut self, account_id: [u8; 32], amount: u64) -> Result<(), &'static str> {
            let account = self.accounts.entry(account_id).or_insert(TokenAccount { balance: 0 });
            
            // VULNERABILITY: No overflow check on addition
            // In release mode with overflow checks disabled, this will wrap around
            account.balance += amount;
            
            Ok(())
        }
        
        /// Vulnerable function that doesn't check for underflow
        pub fn remove_tokens(&mut self, account_id: [u8; 32], amount: u64) -> Result<(), &'static str> {
            let account = match self.accounts.get_mut(&account_id) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // VULNERABILITY: Insufficient underflow protection
            // Only checks if balance is greater than amount, but doesn't handle the case
            // where balance is exactly equal to amount and a malicious fee is added
            if account.balance < amount {
                return Err("Insufficient balance");
            }
            
            // This will underflow if balance is exactly equal to amount and fee is non-zero
            let fee = amount / 100; // 1% fee
            account.balance -= amount + fee; // Potential underflow
            
            Ok(())
        }
    }
}

/// Example of secure code that prevents overflow/underflow
pub mod secure {
    pub struct TokenAccount {
        pub balance: u64,
    }
    
    pub struct TokenProgram {
        pub accounts: std::collections::HashMap<[u8; 32], TokenAccount>,
    }
    
    impl TokenProgram {
        pub fn new() -> Self {
            Self {
                accounts: std::collections::HashMap::new(),
            }
        }
        
        /// Secure function that properly checks for overflow
        pub fn add_tokens(&mut self, account_id: [u8; 32], amount: u64) -> Result<(), &'static str> {
            let account = self.accounts.entry(account_id).or_insert(TokenAccount { balance: 0 });
            
            // FIXED: Use checked_add to safely handle potential overflow
            account.balance = match account.balance.checked_add(amount) {
                Some(new_balance) => new_balance,
                None => return Err("Arithmetic overflow detected"),
            };
            
            Ok(())
        }
        
        /// Secure function that properly checks for underflow
        pub fn remove_tokens(&mut self, account_id: [u8; 32], amount: u64) -> Result<(), &'static str> {
            let account = match self.accounts.get_mut(&account_id) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // Calculate fee safely
            let fee = amount / 100; // 1% fee
            
            // FIXED: Use checked_add to safely check total amount to deduct
            let total_deduction = match amount.checked_add(fee) {
                Some(total) => total,
                None => return Err("Arithmetic overflow detected in fee calculation"),
            };
            
            // Check if balance is sufficient for the total deduction
            if account.balance < total_deduction {
                return Err("Insufficient balance including fees");
            }
            
            // Safe to subtract now
            account.balance -= total_deduction;
            
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_overflow() {
        let mut program = vulnerable::TokenProgram::new();
        let account_id = [1u8; 32];
        
        // Create account with balance close to max
        program.accounts.insert(account_id, vulnerable::TokenAccount {
            balance: u64::MAX - 10,
        });
        
        // This would overflow in release mode with checks disabled
        // For this test, Rust's debug mode will panic
        if cfg!(not(debug_assertions)) {
            let _ = program.add_tokens(account_id, 20);
            // Balance would wrap around to a small number
            // assert_eq!(program.accounts.get(&account_id).unwrap().balance, 9);
        }
    }
    
    #[test]
    fn test_secure_overflow_prevention() {
        let mut program = secure::TokenProgram::new();
        let account_id = [1u8; 32];
        
        // Create account with balance close to max
        program.accounts.insert(account_id, secure::TokenAccount {
            balance: u64::MAX - 10,
        });
        
        // This should return an error instead of overflowing
        let result = program.add_tokens(account_id, 20);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Arithmetic overflow detected");
        
        // Balance should remain unchanged
        assert_eq!(program.accounts.get(&account_id).unwrap().balance, u64::MAX - 10);
    }
}
