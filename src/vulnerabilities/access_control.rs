//! # Access Control Vulnerability
//!
//! Access control vulnerabilities occur when a smart contract fails to properly
//! restrict access to privileged functions, allowing unauthorized users to
//! perform sensitive operations such as withdrawing funds, changing contract
//! parameters, or affecting other users' assets.
//!
//! These vulnerabilities can be especially subtle in Rust smart contracts where
//! ownership patterns and account validation may differ from other platforms.

use crate::vulnerabilities::Vulnerability;

/// Represents an access control vulnerability example
pub struct AccessControlVulnerability;

impl Vulnerability for AccessControlVulnerability {
    fn name(&self) -> &'static str {
        "Access Control Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract fails to properly restrict access to privileged functions, \
        allowing unauthorized users to perform sensitive operations such as withdrawing funds, \
        changing contract parameters, or affecting other users' assets."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All Rust-based contracts"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function with missing access control
        pub fn set_protocol_fee(ctx: Context<SetFee>, new_fee: u64) -> Result<()> {
            // VULNERABILITY: No access control check to restrict who can call this
            // Anyone can change the fee to any value
            
            ctx.accounts.protocol_config.fee_percentage = new_fee;
            
            Ok(())
        }
        
        // Vulnerable function with broken access control
        pub fn update_user_account(ctx: Context<UpdateAccount>, data: UserAccountData) -> Result<()> {
            // VULNERABILITY: Incorrect access validation
            // The function only checks if the provided pubkey matches the expected owner
            // but doesn't verify that the signer actually signed the transaction
            
            if ctx.accounts.user_account.owner != ctx.accounts.authority.key() {
                return Err(ErrorCode::InvalidOwner.into());
            }
            
            // Update account with the new data
            ctx.accounts.user_account.update(data);
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Identify privileged functions and verify appropriate access controls",
            "Check for missing signer verification in sensitive operations", 
            "Review account validation logic, especially in functions that modify state",
            "Look for admin-only functions that lack proper authorization checks",
            "Verify that account ownership is properly enforced in cross-program operations",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Implement proper signer verification for all sensitive operations",
            "Use a well-defined role-based access control (RBAC) system",
            "Ensure all admin functions check for the correct admin authority",
            "Validate account ownership before performing operations on behalf of users",
            "Consider time-locks for critical parameter changes",
        ]
    }
}

/// Example of vulnerable code with access control issues
pub mod vulnerable {
    #[derive(Debug, Clone)]
    pub struct Protocol {
        pub admin: [u8; 32],
        pub fee_percentage: u64,
        pub accounts: std::collections::HashMap<[u8; 32], UserAccount>,
    }
    
    #[derive(Debug, Clone)]
    pub struct UserAccount {
        pub owner: [u8; 32],
        pub balance: u64,
        pub settings: UserSettings,
    }
    
    #[derive(Debug, Clone)]
    pub struct UserSettings {
        pub auto_compound: bool,
        pub withdraw_limit: u64,
    }
    
    impl Protocol {
        pub fn new(admin: [u8; 32]) -> Self {
            Self {
                admin,
                fee_percentage: 10, // 0.1%
                accounts: std::collections::HashMap::new(),
            }
        }
        
        /// Vulnerable function with missing access control
        pub fn set_fee_percentage(&mut self, new_fee: u64) -> Result<(), &'static str> {
            // VULNERABILITY: No access control check
            // Anyone can call this function and change the fee
            
            if new_fee > 10000 {
                return Err("Fee percentage too high");
            }
            
            self.fee_percentage = new_fee;
            
            Ok(())
        }
        
        /// Vulnerable function with improper validation
        pub fn update_user_settings(
            &mut self,
            account_id: [u8; 32],
            caller: [u8; 32],
            new_settings: UserSettings,
        ) -> Result<(), &'static str> {
            let account = match self.accounts.get_mut(&account_id) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // VULNERABILITY: Only checks if caller matches owner in storage
            // But this doesn't verify the caller actually signed the transaction
            // An attacker could just pass in any key they want
            if account.owner != caller {
                return Err("Not the account owner");
            }
            
            account.settings = new_settings;
            
            Ok(())
        }
        
        /// Vulnerable function allowing account ownership transfer
        pub fn transfer_account_ownership(
            &mut self,
            account_id: [u8; 32],
            provided_owner: [u8; 32],
            new_owner: [u8; 32],
        ) -> Result<(), &'static str> {
            let account = match self.accounts.get_mut(&account_id) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // VULNERABILITY: Same issue - only matching the key without signature verification
            if account.owner != provided_owner {
                return Err("Not the account owner");
            }
            
            // VULNERABILITY: No validation on the new_owner
            // Could be set to something invalid or malicious
            account.owner = new_owner;
            
            Ok(())
        }
    }
}

/// Example of secure code with proper access control
pub mod secure {
    #[derive(Debug, Clone)]
    pub struct Protocol {
        pub admin: [u8; 32],
        pub pending_admin: Option<[u8; 32]>,
        pub admin_change_time: Option<u64>,
        pub fee_percentage: u64,
        pub accounts: std::collections::HashMap<[u8; 32], UserAccount>,
        pub current_time: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct UserAccount {
        pub owner: [u8; 32],
        pub balance: u64,
        pub settings: UserSettings,
        pub authorized_signers: Vec<[u8; 32]>,
    }
    
    #[derive(Debug, Clone)]
    pub struct UserSettings {
        pub auto_compound: bool,
        pub withdraw_limit: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct Transaction {
        pub caller: [u8; 32],
        pub signature: [u8; 64],
        pub valid: bool, // In a real implementation, would verify the signature
    }
    
    impl Protocol {
        pub fn new(admin: [u8; 32]) -> Self {
            Self {
                admin,
                pending_admin: None,
                admin_change_time: None,
                fee_percentage: 10, // 0.1%
                accounts: std::collections::HashMap::new(),
                current_time: 0,
            }
        }
        
        /// Secure function with proper access control
        pub fn set_fee_percentage(&mut self, tx: &Transaction, new_fee: u64) -> Result<(), &'static str> {
            // FIXED: Proper access control check
            
            // Verify the transaction is valid (signature check)
            if !tx.valid {
                return Err("Invalid transaction");
            }
            
            // Check that the caller is the admin
            if tx.caller != self.admin {
                return Err("Only admin can change fee percentage");
            }
            
            if new_fee > 10000 {
                return Err("Fee percentage too high");
            }
            
            self.fee_percentage = new_fee;
            
            Ok(())
        }
        
        /// Secure function with proper validation
        pub fn update_user_settings(
            &mut self,
            tx: &Transaction,
            account_id: [u8; 32],
            new_settings: UserSettings,
        ) -> Result<(), &'static str> {
            // FIXED: Verify transaction validity first
            if !tx.valid {
                return Err("Invalid transaction");
            }
            
            let account = match self.accounts.get_mut(&account_id) {
                Some(account) => account,
                None => return Err("Account not found"),
            };
            
            // FIXED: Check that the caller is authorized
            let is_owner = account.owner == tx.caller;
            let is_authorized = account.authorized_signers.contains(&tx.caller);
            
            if !is_owner && !is_authorized {
                return Err("Not authorized to update settings");
            }
            
            // Validate settings
            if new_settings.withdraw_limit > 1_000_000_000 {
                return Err("Withdraw limit too high");
            }
            
            account.settings = new_settings;
            
            Ok(())
        }
        
        /// Secure version of admin transfer with timelock
        pub fn initiate_admin_transfer(&mut self, tx: &Transaction, new_admin: [u8; 32]) -> Result<(), &'static str> {
            // Verify transaction and admin status
            if !tx.valid {
                return Err("Invalid transaction");
            }
            
            if tx.caller != self.admin {
                return Err("Only current admin can initiate transfer");
            }
            
            // Set pending admin with timelock
            self.pending_admin = Some(new_admin);
            self.admin_change_time = Some(self.current_time + 86400); // 24-hour timelock
            
            Ok(())
        }
        
        /// Second step of admin transfer with timelock
        pub fn complete_admin_transfer(&mut self, tx: &Transaction) -> Result<(), &'static str> {
            // Verify transaction validity
            if !tx.valid {
                return Err("Invalid transaction");
            }
            
            // Check pending admin exists and caller is the pending admin
            match self.pending_admin {
                Some(pending_admin) if pending_admin == tx.caller => {
                    // Check if timelock has elapsed
                    match self.admin_change_time {
                        Some(change_time) if self.current_time >= change_time => {
                            self.admin = pending_admin;
                            self.pending_admin = None;
                            self.admin_change_time = None;
                            Ok(())
                        },
                        _ => Err("Timelock has not expired yet"),
                    }
                },
                _ => Err("Not the pending admin or no admin transfer in progress"),
            }
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
    fn test_vulnerable_access_control() {
        let mut protocol = vulnerable::Protocol::new([1u8; 32]); // Admin
        let user = [2u8; 32];
        let attacker = [3u8; 32];
        
        // Attacker can change the protocol fee despite not being admin
        let result = protocol.set_fee_percentage(5000); // 50%
        assert!(result.is_ok());
        assert_eq!(protocol.fee_percentage, 5000);
        
        // Create a user account
        protocol.accounts.insert(user, vulnerable::UserAccount {
            owner: user,
            balance: 1000,
            settings: vulnerable::UserSettings {
                auto_compound: false,
                withdraw_limit: 100,
            },
        });
        
        // Attacker can update someone else's account settings by just passing the victim's key
        // In a real system with signature verification this wouldn't work, but here we're just
        // simulating the vulnerability
        let result = protocol.update_user_settings(
            user, // account_id
            user, // just passing the correct owner key
            vulnerable::UserSettings {
                auto_compound: true,
                withdraw_limit: 1000,
            },
        );
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_secure_access_control() {
        let mut protocol = secure::Protocol::new([1u8; 32]); // Admin
        let user = [2u8; 32];
        let attacker = [3u8; 32];
        
        // Create valid transactions (in reality, these would have valid signatures)
        let admin_tx = secure::Transaction {
            caller: [1u8; 32],
            signature: [0u8; 64],
            valid: true,
        };
        
        let attacker_tx = secure::Transaction {
            caller: attacker,
            signature: [0u8; 64],
            valid: true,
        };
        
        // Attacker cannot change the protocol fee
        let result = protocol.set_fee_percentage(&attacker_tx, 5000);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Only admin can change fee percentage");
        
        // Admin can change the fee
        let result = protocol.set_fee_percentage(&admin_tx, 20); // 0.2%
        assert!(result.is_ok());
        assert_eq!(protocol.fee_percentage, 20);
        
        // Test admin transfer with timelock
        let new_admin = [4u8; 32];
        let new_admin_tx = secure::Transaction {
            caller: new_admin,
            signature: [0u8; 64],
            valid: true,
        };
        
        // Initiate transfer
        let result = protocol.initiate_admin_transfer(&admin_tx, new_admin);
        assert!(result.is_ok());
        
        // Cannot complete before timelock expires
        let result = protocol.complete_admin_transfer(&new_admin_tx);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Timelock has not expired yet");
        
        // Advance time
        protocol.advance_time(86401); // Just over 24 hours
        
        // Now can complete the transfer
        let result = protocol.complete_admin_transfer(&new_admin_tx);
        assert!(result.is_ok());
        assert_eq!(protocol.admin, new_admin);
    }
}
