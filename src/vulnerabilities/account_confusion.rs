//! # Account Confusion Vulnerability
//!
//! Account confusion vulnerabilities occur when a smart contract fails to properly validate
//! the identity or type of accounts it interacts with, allowing attackers to substitute unexpected
//! accounts and manipulate program execution.
//!
//! In Rust smart contracts on Solana, these vulnerabilities commonly manifest through:
//! - Missing or improper account validation
//! - Not checking account ownership
//! - Not verifying Program Derived Addresses (PDAs)
//! - Cross-instance attacks where one instance's data is used in another instance

use crate::vulnerabilities::Vulnerability;
use crate::utils::{Account, MockBlockchain};

/// Represents an account confusion vulnerability example
pub struct AccountConfusionVulnerability;

impl Vulnerability for AccountConfusionVulnerability {
    fn name(&self) -> &'static str {
        "Account Confusion Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract fails to properly validate the identity or type of accounts \
        it interacts with, allowing attackers to substitute unexpected accounts. This is particularly \
        relevant on Solana where programs operate on accounts passed to them by the transaction."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable account validation in a Solana program
        pub fn process_instruction(
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            
            let user_account = next_account_info(accounts_iter)?;
            let vault_account = next_account_info(accounts_iter)?;
            let token_program = next_account_info(accounts_iter)?;
            
            // VULNERABILITY: Not validating that vault_account is actually the intended vault
            // An attacker could substitute their own account here
            
            // Extract instruction data
            let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
            
            // Transfer tokens from vault to user
            let transfer_instruction = solana_program::instruction::Instruction {
                program_id: *token_program.key,
                accounts: vec![
                    AccountMeta::new(*vault_account.key, false),
                    AccountMeta::new(*user_account.key, false),
                    AccountMeta::new_readonly(*program_id, true),
                ],
                data: /* token transfer instruction */,
            };
            
            invoke_signed(
                &transfer_instruction,
                &[vault_account.clone(), user_account.clone(), program_id.clone()],
                &[&[/* PDA seeds */]],
            )?;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Verify that all account ownership checks are implemented correctly",
            "Check that PDA validation includes bump seed verification",
            "Validate that expected program IDs are explicitly checked",
            "Ensure all account types are validated before use",
            "Verify that the correct account is used in each context",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Always validate account ownership",
            "Properly derive and check PDAs with the correct seeds and bump",
            "Explicitly validate all program IDs for cross-program invocations",
            "Use explicit account type checking for each account",
            "Implement a comprehensive account validation framework",
        ]
    }
}

/// Module containing a vulnerable implementation
pub mod vulnerable {
    use std::collections::HashMap;
    
    /// A simplified Solana-style program with vulnerable account validation
    pub struct VaultProgram {
        pub vault_address: [u8; 32], // The intended vault address
        pub token_accounts: HashMap<[u8; 32], TokenAccount>,
        pub program_id: [u8; 32],
    }
    
    /// Token account structure
    pub struct TokenAccount {
        pub owner: [u8; 32],
        pub balance: u64,
    }
    
    impl VaultProgram {
        /// Create a new vault program
        pub fn new(program_id: [u8; 32], vault_address: [u8; 32]) -> Self {
            let mut token_accounts = HashMap::new();
            
            // Create the vault account with some initial tokens
            token_accounts.insert(vault_address, TokenAccount {
                owner: program_id,
                balance: 1000000,
            });
            
            Self {
                vault_address,
                token_accounts,
                program_id,
            }
        }
        
        /// Withdraw tokens with vulnerable account validation
        pub fn withdraw(&mut self, 
                        user_address: [u8; 32], 
                        vault_address: [u8; 32], // VULNERABILITY: This should be validated
                        amount: u64) -> Result<(), &'static str> {
            
            // VULNERABILITY: No validation that vault_address is the correct vault
            // An attacker could pass in any account they control
            
            // Get the vault account
            let vault_account = self.token_accounts.get_mut(&vault_address)
                .ok_or("Vault account not found")?;
            
            // Check balance
            if vault_account.balance < amount {
                return Err("Insufficient funds in vault");
            }
            
            // Create user account if it doesn't exist
            if !self.token_accounts.contains_key(&user_address) {
                self.token_accounts.insert(user_address, TokenAccount {
                    owner: user_address,
                    balance: 0,
                });
            }
            
            // Process transfer
            vault_account.balance -= amount;
            self.token_accounts.get_mut(&user_address).unwrap().balance += amount;
            
            Ok(())
        }
    }
}

/// Module containing a secure implementation
pub mod secure {
    use std::collections::HashMap;
    
    /// A Solana-style program with secure account validation
    pub struct VaultProgram {
        pub vault_address: [u8; 32], // The intended vault address
        pub token_accounts: HashMap<[u8; 32], TokenAccount>,
        pub program_id: [u8; 32],
    }
    
    /// Token account structure
    pub struct TokenAccount {
        pub owner: [u8; 32],
        pub balance: u64,
    }
    
    impl VaultProgram {
        /// Create a new vault program
        pub fn new(program_id: [u8; 32], vault_address: [u8; 32]) -> Self {
            let mut token_accounts = HashMap::new();
            
            // Create the vault account with some initial tokens
            token_accounts.insert(vault_address, TokenAccount {
                owner: program_id,
                balance: 1000000,
            });
            
            Self {
                vault_address,
                token_accounts,
                program_id,
            }
        }
        
        /// Withdraw tokens with secure account validation
        pub fn withdraw(&mut self, 
                        user_address: [u8; 32], 
                        amount: u64) -> Result<(), &'static str> {
            
            // SECURE: Using the known vault address stored in the program state
            // rather than accepting any address from the user
            let vault_address = self.vault_address;
            
            // Get the vault account
            let vault_account = self.token_accounts.get_mut(&vault_address)
                .ok_or("Vault account not found")?;
            
            // SECURE: Validate that the vault is owned by the program
            if vault_account.owner != self.program_id {
                return Err("Vault account has invalid ownership");
            }
            
            // Check balance
            if vault_account.balance < amount {
                return Err("Insufficient funds in vault");
            }
            
            // Create user account if it doesn't exist
            if !self.token_accounts.contains_key(&user_address) {
                self.token_accounts.insert(user_address, TokenAccount {
                    owner: user_address,
                    balance: 0,
                });
            }
            
            // Process transfer
            vault_account.balance -= amount;
            self.token_accounts.get_mut(&user_address).unwrap().balance += amount;
            
            Ok(())
        }
    }
}
