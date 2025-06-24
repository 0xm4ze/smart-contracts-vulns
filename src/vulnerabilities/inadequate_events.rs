//! # Inadequate Event Emissions Vulnerability
//!
//! Inadequate event emissions vulnerabilities occur when smart contracts fail to emit 
//! critical events for important state changes or operations, making it difficult to
//! monitor the contract's behavior off-chain and detect malicious activity.
//!
//! In Rust smart contracts, these vulnerabilities manifest through:
//! - Missing events for critical operations
//! - Events with insufficient information
//! - Inconsistent event emissions

use crate::vulnerabilities::Vulnerability;
use crate::utils::{Account, MockBlockchain};

/// Represents an inadequate event emissions vulnerability example
pub struct InadequateEventsVulnerability;

impl Vulnerability for InadequateEventsVulnerability {
    fn name(&self) -> &'static str {
        "Inadequate Event Emissions Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract fails to emit appropriate events for critical operations, \
        making it difficult to track important state changes off-chain. This can lead to security \
        issues as suspicious activities may go unnoticed without proper monitoring."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "CosmWasm"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable implementation with missing event emissions
        pub fn update_admin(ctx: Context<UpdateAdmin>, new_admin: Pubkey) -> Result<()> {
            // VULNERABILITY: Critical operation without event emission
            // Changing the admin address is a security-critical operation
            // that should be logged with an event
            
            ctx.accounts.config.admin = new_admin;
            
            Ok(())
        }
        
        pub fn withdraw_funds(ctx: Context<WithdrawFunds>, amount: u64) -> Result<()> {
            // Check that the caller is the admin
            if ctx.accounts.authority.key() != ctx.accounts.config.admin {
                return Err(ErrorCode::Unauthorized.into());
            }
            
            // VULNERABILITY: No event emitted for fund withdrawal
            // This makes it difficult to track fund movements off-chain
            
            // Transfer funds
            let transfer_instruction = transfer(
                ctx.accounts.treasury.to_account_info().key,
                ctx.accounts.recipient.to_account_info().key,
                amount,
            );
            
            invoke_signed(
                &transfer_instruction,
                &[
                    ctx.accounts.treasury.to_account_info(),
                    ctx.accounts.recipient.to_account_info(),
                ],
                &[&[/* seeds */]],
            )?;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Identify all critical state changes and verify they emit appropriate events",
            "Check that sensitive operations like role changes emit detailed events",
            "Verify financial transactions (deposits, withdrawals, transfers) emit events",
            "Ensure events contain sufficient information for off-chain monitoring",
            "Check for consistent event emission patterns across similar operations",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Emit events for all critical state changes",
            "Include detailed information in events (actors, amounts, timestamps)",
            "Implement a consistent event emission policy across the contract",
            "Use a standardized event structure for similar operations",
            "Ensure events capture both the previous and new state for important changes",
        ]
    }
}

/// Module containing a vulnerable implementation
pub mod vulnerable {
    use std::collections::HashMap;
    
    /// Configuration for the program
    pub struct Config {
        pub admin: [u8; 32],
    }
    
    /// A simplified program with inadequate event emissions
    pub struct Program {
        pub config: Config,
        pub treasury_balance: u64,
        pub accounts: HashMap<[u8; 32], u64>,
    }
    
    impl Program {
        /// Create a new program
        pub fn new(admin: [u8; 32]) -> Self {
            Self {
                config: Config { admin },
                treasury_balance: 1000000,
                accounts: HashMap::new(),
            }
        }
        
        /// Update admin with no event emission
        pub fn update_admin(&mut self, caller: [u8; 32], new_admin: [u8; 32]) -> Result<(), &'static str> {
            // Check authorization
            if caller != self.config.admin {
                return Err("Unauthorized");
            }
            
            // VULNERABILITY: Critical operation without event emission
            self.config.admin = new_admin;
            
            Ok(())
        }
        
        /// Withdraw funds with no event emission
        pub fn withdraw(&mut self, caller: [u8; 32], recipient: [u8; 32], amount: u64) -> Result<(), &'static str> {
            // Check authorization
            if caller != self.config.admin {
                return Err("Unauthorized");
            }
            
            // Check balance
            if self.treasury_balance < amount {
                return Err("Insufficient funds");
            }
            
            // Update balances
            self.treasury_balance -= amount;
            
            // Create recipient account if it doesn't exist
            if !self.accounts.contains_key(&recipient) {
                self.accounts.insert(recipient, 0);
            }
            
            // Add to recipient
            *self.accounts.get_mut(&recipient).unwrap() += amount;
            
            // VULNERABILITY: No event emitted for fund withdrawal
            
            Ok(())
        }
    }
}

/// Module containing a secure implementation
pub mod secure {
    use std::collections::HashMap;
    
    /// Event structure for admin changes
    #[derive(Debug)]
    pub struct AdminChangedEvent {
        pub previous_admin: [u8; 32],
        pub new_admin: [u8; 32],
        pub timestamp: u64,
    }
    
    /// Event structure for withdrawals
    #[derive(Debug)]
    pub struct WithdrawalEvent {
        pub initiator: [u8; 32],
        pub recipient: [u8; 32],
        pub amount: u64,
        pub timestamp: u64,
    }
    
    /// Configuration for the program
    pub struct Config {
        pub admin: [u8; 32],
    }
    
    /// A program with proper event emissions
    pub struct Program {
        pub config: Config,
        pub treasury_balance: u64,
        pub accounts: HashMap<[u8; 32], u64>,
        pub admin_events: Vec<AdminChangedEvent>,
        pub withdrawal_events: Vec<WithdrawalEvent>,
    }
    
    impl Program {
        /// Create a new program
        pub fn new(admin: [u8; 32]) -> Self {
            Self {
                config: Config { admin },
                treasury_balance: 1000000,
                accounts: HashMap::new(),
                admin_events: Vec::new(),
                withdrawal_events: Vec::new(),
            }
        }
        
        /// Update admin with proper event emission
        pub fn update_admin(&mut self, caller: [u8; 32], new_admin: [u8; 32], timestamp: u64) -> Result<(), &'static str> {
            // Check authorization
            if caller != self.config.admin {
                return Err("Unauthorized");
            }
            
            // Store the previous admin for the event
            let previous_admin = self.config.admin;
            
            // Update the admin
            self.config.admin = new_admin;
            
            // SECURE: Emit an event for the admin change
            self.admin_events.push(AdminChangedEvent {
                previous_admin,
                new_admin,
                timestamp,
            });
            
            Ok(())
        }
        
        /// Withdraw funds with proper event emission
        pub fn withdraw(&mut self, caller: [u8; 32], recipient: [u8; 32], amount: u64, timestamp: u64) -> Result<(), &'static str> {
            // Check authorization
            if caller != self.config.admin {
                return Err("Unauthorized");
            }
            
            // Check balance
            if self.treasury_balance < amount {
                return Err("Insufficient funds");
            }
            
            // Update balances
            self.treasury_balance -= amount;
            
            // Create recipient account if it doesn't exist
            if !self.accounts.contains_key(&recipient) {
                self.accounts.insert(recipient, 0);
            }
            
            // Add to recipient
            *self.accounts.get_mut(&recipient).unwrap() += amount;
            
            // SECURE: Emit an event for the withdrawal
            self.withdrawal_events.push(WithdrawalEvent {
                initiator: caller,
                recipient,
                amount,
                timestamp,
            });
            
            Ok(())
        }
    }
}
