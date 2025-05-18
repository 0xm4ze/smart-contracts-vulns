//! # Unchecked Inputs Vulnerability
//!
//! Unchecked inputs vulnerabilities occur when a smart contract fails to validate
//! user-provided data, potentially leading to various attacks including injection,
//! manipulation of contract state, or bypassing security controls.
//!
//! This is especially important in Rust contracts where deserialization and type
//! conversion might appear safe but still require validation of logical constraints.

use crate::vulnerabilities::Vulnerability;

/// Represents an unchecked inputs vulnerability example
pub struct UncheckedInputsVulnerability;

impl Vulnerability for UncheckedInputsVulnerability {
    fn name(&self) -> &'static str {
        "Unchecked Inputs Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract fails to validate user-provided data, \
        potentially leading to various attacks including injection, manipulation \
        of contract state, or bypassing security controls."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All Rust-based contracts"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function that doesn't validate inputs properly
        pub fn process_transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
            // VULNERABILITY: No validation on the amount
            // The amount could be 0, causing a no-op transfer
            // or extremely large, causing other issues
            
            ctx.accounts.source.balance -= amount;
            ctx.accounts.destination.balance += amount;
            
            Ok(())
        }
        
        // Vulnerable function that trusts deserialized data
        pub fn process_transaction(ctx: Context<ProcessTx>, tx_data: Vec<u8>) -> Result<()> {
            // VULNERABILITY: Doesn't check bounds, patterns, or constraints
            // after deserialization
            let transaction: Transaction = borsh::BorshDeserialize::deserialize(&tx_data[..])
                .map_err(|_| ErrorCode::InvalidTransaction)?;
            
            // Uses transaction data without additional validation
            process_validated_transaction(ctx, transaction)
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Look for functions that receive external inputs without validation",
            "Check for missing boundary checks on numerical inputs",
            "Look for deserialization of complex structures without validation",
            "Verify validation logic on arguments that could affect program flow",
            "Examine type conversions that might truncate or alter values",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Implement comprehensive input validation for all user-provided data",
            "Use Rust's type system to enforce constraints where possible",
            "Add explicit boundary checks for numerical values",
            "Validate deserialized data after deserialization",
            "Consider using libraries like 'validator' for complex validation logic",
        ]
    }
}

/// Example of vulnerable code with unchecked inputs
pub mod vulnerable {
    #[derive(Debug, Clone)]
    pub struct UserAccount {
        pub owner: [u8; 32],
        pub balance: u64,
        pub authorized_delegates: Vec<[u8; 32]>,
    }
    
    pub struct BankProgram {
        pub accounts: std::collections::HashMap<[u8; 32], UserAccount>,
    }
    
    impl BankProgram {
        pub fn new() -> Self {
            Self {
                accounts: std::collections::HashMap::new(),
            }
        }
        
        /// Vulnerable function that doesn't validate input amounts
        pub fn transfer(&mut self, sender: [u8; 32], recipient: [u8; 32], amount: u64) -> Result<(), &'static str> {
            // Get sender account
            let sender_account = match self.accounts.get(&sender) {
                Some(account) => account,
                None => return Err("Sender account not found"),
            };
            
            // VULNERABILITY: No validation on the amount
            // - Doesn't check if amount is zero (allows no-op transfers)
            // - Doesn't check if amount is reasonable (could be extremely large)
            
            if sender_account.balance < amount {
                return Err("Insufficient balance");
            }
            
            // Perform transfer
            let sender_account = self.accounts.get_mut(&sender).unwrap();
            sender_account.balance -= amount;
            
            let recipient_account = self.accounts.entry(recipient).or_insert(UserAccount {
                owner: recipient,
                balance: 0,
                authorized_delegates: Vec::new(),
            });
            recipient_account.balance += amount;
            
            Ok(())
        }
        
        /// Vulnerable function that doesn't validate delegates properly
        pub fn add_delegate(&mut self, account: [u8; 32], delegate: [u8; 32]) -> Result<(), &'static str> {
            let user_account = match self.accounts.get_mut(&account) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // VULNERABILITY: No validation on the delegate
            // - Doesn't check if delegate is already in the list
            // - Doesn't check if delegate is the same as the owner
            // - Doesn't limit the number of delegates
            
            user_account.authorized_delegates.push(delegate);
            
            Ok(())
        }
    }
}

/// Example of secure code with proper input validation
pub mod secure {
    #[derive(Debug, Clone)]
    pub struct UserAccount {
        pub owner: [u8; 32],
        pub balance: u64,
        pub authorized_delegates: Vec<[u8; 32]>,
    }
    
    pub struct BankProgram {
        pub accounts: std::collections::HashMap<[u8; 32], UserAccount>,
    }
    
    impl BankProgram {
        pub fn new() -> Self {
            Self {
                accounts: std::collections::HashMap::new(),
            }
        }
        
        /// Secure function with proper input validation
        pub fn transfer(&mut self, sender: [u8; 32], recipient: [u8; 32], amount: u64) -> Result<(), &'static str> {
            // FIXED: Validate inputs
            
            // Check for zero amount
            if amount == 0 {
                return Err("Amount must be greater than zero");
            }
            
            // Check for reasonable limits
            const MAX_TRANSFER: u64 = 1_000_000_000_000; // Example limit
            if amount > MAX_TRANSFER {
                return Err("Amount exceeds maximum transfer limit");
            }
            
            // Check for self-transfer
            if sender == recipient {
                return Err("Cannot transfer to self");
            }
            
            // Get sender account
            let sender_account = match self.accounts.get(&sender) {
                Some(account) => account,
                None => return Err("Sender account not found"),
            };
            
            if sender_account.balance < amount {
                return Err("Insufficient balance");
            }
            
            // Perform transfer
            let sender_account = self.accounts.get_mut(&sender).unwrap();
            sender_account.balance -= amount;
            
            let recipient_account = self.accounts.entry(recipient).or_insert(UserAccount {
                owner: recipient,
                balance: 0,
                authorized_delegates: Vec::new(),
            });
            recipient_account.balance += amount;
            
            Ok(())
        }
        
        /// Secure function with proper delegate validation
        pub fn add_delegate(&mut self, account: [u8; 32], delegate: [u8; 32]) -> Result<(), &'static str> {
            // FIXED: Validate inputs
            
            // Check for self-delegation
            if account == delegate {
                return Err("Cannot add self as delegate");
            }
            
            let user_account = match self.accounts.get_mut(&account) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // Check if delegate is already in the list
            if user_account.authorized_delegates.contains(&delegate) {
                return Err("Delegate already authorized");
            }
            
            // Check maximum number of delegates
            const MAX_DELEGATES: usize = 5; // Example limit
            if user_account.authorized_delegates.len() >= MAX_DELEGATES {
                return Err("Maximum number of delegates reached");
            }
            
            user_account.authorized_delegates.push(delegate);
            
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_unchecked_inputs() {
        let mut program = vulnerable::BankProgram::new();
        let account_id = [1u8; 32];
        
        // Create account with 100 tokens
        program.accounts.insert(account_id, vulnerable::UserAccount {
            owner: account_id,
            balance: 100,
            authorized_delegates: Vec::new(),
        });
        
        // Zero amount transfer succeeds in vulnerable implementation
        let result = program.transfer(account_id, [2u8; 32], 0);
        assert!(result.is_ok());
        
        // Self-delegation succeeds in vulnerable implementation
        let result = program.add_delegate(account_id, account_id);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_secure_input_validation() {
        let mut program = secure::BankProgram::new();
        let account_id = [1u8; 32];
        
        // Create account with 100 tokens
        program.accounts.insert(account_id, secure::UserAccount {
            owner: account_id,
            balance: 100,
            authorized_delegates: Vec::new(),
        });
        
        // Zero amount transfer fails in secure implementation
        let result = program.transfer(account_id, [2u8; 32], 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Amount must be greater than zero");
        
        // Self-delegation fails in secure implementation
        let result = program.add_delegate(account_id, account_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Cannot add self as delegate");
    }
}
