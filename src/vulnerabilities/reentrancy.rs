//! # Reentrancy Vulnerability
//!
//! Reentrancy vulnerabilities occur when a contract function can be called repeatedly
//! before the first invocation is complete, allowing an attacker to manipulate the
//! contract's state in unexpected ways.
//!
//! In Rust smart contracts (particularly on platforms like Solana), reentrancy often 
//! manifests through cross-program invocation (CPI) where the callee can call back 
//! into the caller.

use crate::vulnerabilities::Vulnerability;
use crate::utils::{Account, MockBlockchain};

/// Represents a reentrancy vulnerability example
pub struct ReentrancyVulnerability;

impl Vulnerability for ReentrancyVulnerability {
    fn name(&self) -> &'static str {
        "Reentrancy Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a contract function can be re-entered before the first call completes, \
        allowing an attacker to manipulate state in unexpected ways. In Rust smart contracts, \
        this typically happens through cross-program invocation (CPI) mechanisms."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable contract that doesn't follow checks-effects-interactions pattern
        pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
            let user_balance = ctx.accounts.user_account.balance;
            
            if user_balance < amount {
                return Err(ErrorCode::InsufficientFunds.into());
            }
            
            // VULNERABILITY: Transfer happens before state update
            // This allows the recipient to call back into this function before
            // the balance is updated
            transfer_tokens(ctx.accounts.recipient.key, amount)?;
            
            // State is updated after the external call
            ctx.accounts.user_account.balance -= amount;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Look for state changes that occur after external calls or cross-program invocations",
            "Check if the contract uses a reentrancy guard",
            "Verify that the checks-effects-interactions pattern is followed",
            "Examine cross-program invocation permissions",
            "Check for proper handling of account validation",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Follow the checks-effects-interactions pattern: validate conditions, update state, then make external calls",
            "Implement reentrancy guards using a mutex-like mechanism",
            "Use Rust's type system to prevent reentrancy by design",
            "Minimize cross-program invocations where possible",
            "Carefully consider which accounts have invocation privileges",
        ]
    }
}

/// Example of vulnerable code susceptible to reentrancy
pub mod vulnerable {
    use super::*;
    
    pub struct VaultAccount {
        pub owner: [u8; 32],
        pub balance: u64,
    }
    
    pub struct VaultProgram {
        pub accounts: std::collections::HashMap<[u8; 32], VaultAccount>,
    }
    
    impl VaultProgram {
        pub fn new() -> Self {
            Self {
                accounts: std::collections::HashMap::new(),
            }
        }
        
        /// Vulnerable withdraw function
        pub fn withdraw(&mut self, caller: [u8; 32], recipient: [u8; 32], amount: u64) -> Result<(), &'static str> {
            // Get account
            let account = match self.accounts.get(&caller) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // Check balance
            if account.balance < amount {
                return Err("Insufficient balance");
            }
            
            // VULNERABILITY: External call before state update
            // In a real blockchain, this would be a cross-program invocation
            // that could call back into this function
            self.transfer_tokens(caller, recipient, amount)?;
            
            // Update state AFTER the external call
            let account = self.accounts.get_mut(&caller).unwrap();
            account.balance -= amount;
            
            Ok(())
        }
        
        /// Mock function to simulate token transfer
        fn transfer_tokens(&mut self, _from: [u8; 32], _to: [u8; 32], _amount: u64) -> Result<(), &'static str> {
            // In a real exploit, the recipient would call back into withdraw()
            // before this completes, causing a reentrancy attack
            Ok(())
        }
    }
}

/// Example of secure code that prevents reentrancy
pub mod secure {
    use super::*;
    
    pub struct VaultAccount {
        pub owner: [u8; 32],
        pub balance: u64,
    }
    
    pub struct VaultProgram {
        pub accounts: std::collections::HashMap<[u8; 32], VaultAccount>,
        pub reentrancy_lock: bool,
    }
    
    impl VaultProgram {
        pub fn new() -> Self {
            Self {
                accounts: std::collections::HashMap::new(),
                reentrancy_lock: false,
            }
        }
        
        /// Secure withdraw function using checks-effects-interactions pattern
        pub fn withdraw(&mut self, caller: [u8; 32], recipient: [u8; 32], amount: u64) -> Result<(), &'static str> {
            // Reentrancy guard
            if self.reentrancy_lock {
                return Err("Reentrant call detected");
            }
            self.reentrancy_lock = true;
            
            // Get account
            let account = match self.accounts.get(&caller) {
                Some(account) => account,
                None => {
                    self.reentrancy_lock = false;
                    return Err("Account not found");
                }
            };
            
            // Check balance
            if account.balance < amount {
                self.reentrancy_lock = false;
                return Err("Insufficient balance");
            }
            
            // FIXED: Update state BEFORE external calls
            let account = self.accounts.get_mut(&caller).unwrap();
            account.balance -= amount;
            
            // Now safe to make external calls
            let result = self.transfer_tokens(caller, recipient, amount);
            
            // Release lock
            self.reentrancy_lock = false;
            
            result
        }
        
        /// Mock function to simulate token transfer
        fn transfer_tokens(&mut self, _from: [u8; 32], _to: [u8; 32], _amount: u64) -> Result<(), &'static str> {
            // Even if this calls back into withdraw(), the reentrancy guard will prevent issues
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_reentrancy() {
        // This is a simplified test that demonstrates the concept
        // A full test would simulate the actual reentrancy attack
        
        let mut program = vulnerable::VaultProgram::new();
        let owner = [1u8; 32];
        let recipient = [2u8; 32];
        
        // Create account with 100 tokens
        program.accounts.insert(owner, vulnerable::VaultAccount {
            owner,
            balance: 100,
        });
        
        // First withdraw
        let _ = program.withdraw(owner, recipient, 50);
        assert_eq!(program.accounts.get(&owner).unwrap().balance, 50);
        
        // In a real attack, the recipient would call back into withdraw
        // before the balance is updated, allowing multiple withdrawals
    }
    
    #[test]
    fn test_secure_reentrancy_prevention() {
        let mut program = secure::VaultProgram::new();
        let owner = [1u8; 32];
        let recipient = [2u8; 32];
        
        // Create account with 100 tokens
        program.accounts.insert(owner, secure::VaultAccount {
            owner,
            balance: 100,
        });
        
        // First withdraw succeeds
        let _ = program.withdraw(owner, recipient, 50);
        assert_eq!(program.accounts.get(&owner).unwrap().balance, 50);
        
        // If a reentrancy were attempted, it would fail due to the lock
    }
}
