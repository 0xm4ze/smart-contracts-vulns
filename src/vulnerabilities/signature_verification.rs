//! # Signature Verification Bypass Vulnerability
//!
//! Signature verification bypass vulnerabilities occur when a smart contract improperly validates
//! signatures, allowing attackers to spoof authorization or execute unauthorized operations.
//!
//! In Rust smart contracts, these vulnerabilities can manifest through:
//! - Incorrect signature verification algorithms
//! - Failing to check all relevant transaction data when verifying signatures
//! - Replay attacks due to missing or improper nonce handling
//! - Signature malleability issues

use crate::vulnerabilities::Vulnerability;
use crate::utils::{Account, MockBlockchain};

/// Represents a signature verification bypass vulnerability example
pub struct SignatureVerificationVulnerability;

impl Vulnerability for SignatureVerificationVulnerability {
    fn name(&self) -> &'static str {
        "Signature Verification Bypass Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract fails to properly validate cryptographic signatures, \
        allowing attackers to forge authorizations or bypass security checks. Common issues include \
        improper verification logic, missing replay protection, and signature malleability problems."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "CosmWasm"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable signature verification that doesn't check all relevant data
        pub fn process_authorized_transaction(
            ctx: Context<AuthorizedTransaction>,
            amount: u64,
            signature: [u8; 64],
        ) -> Result<()> {
            let signer_pubkey = ctx.accounts.authority.key();
            let message = amount.to_le_bytes();
            
            // VULNERABILITY: Only signing the amount, not including recipient or nonce
            // This allows signature reuse for different recipients
            if !verify_signature(&signer_pubkey, &message, &signature) {
                return Err(ErrorCode::InvalidSignature.into());
            }
            
            // Process the transfer...
            transfer_funds(ctx.accounts.from.key, ctx.accounts.to.key, amount)?;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Check that all relevant transaction data is included in the signed message (amount, recipient, timestamp/nonce)",
            "Verify that signatures cannot be reused across different contexts",
            "Ensure proper nonce handling to prevent replay attacks",
            "Check for signature malleability issues in the verification logic",
            "Validate that the signature verification is using appropriate cryptographic algorithms",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Include all relevant transaction data in the signed message",
            "Implement proper nonce handling to prevent replay attacks",
            "Use established cryptographic libraries for signature verification",
            "Add transaction context to the signed message (program ID, instruction type)",
            "Implement domain separation in signatures to prevent cross-contract replay",
        ]
    }
}

/// Module containing a vulnerable implementation
pub mod vulnerable {
    use std::collections::HashMap;
    
    /// A simplified wallet program with vulnerable signature verification
    pub struct WalletProgram {
        pub accounts: HashMap<[u8; 32], WalletAccount>,
    }
    
    /// Wallet account structure
    pub struct WalletAccount {
        pub owner: [u8; 32],
        pub balance: u64,
    }
    
    impl WalletProgram {
        /// Create a new wallet program
        pub fn new() -> Self {
            Self {
                accounts: HashMap::new(),
            }
        }
        
        /// Transfer with vulnerable signature verification
        pub fn transfer(&mut self, 
                        from: [u8; 32], 
                        to: [u8; 32], 
                        amount: u64, 
                        signature: [u8; 64]) -> Result<(), &'static str> {
            // Get the account or return an error
            let from_account = self.accounts.get(&from)
                .ok_or("Account not found")?;
            
            // Check balance
            if from_account.balance < amount {
                return Err("Insufficient funds");
            }
            
            // VULNERABILITY: Only the amount is signed, not the recipient
            // This allows the signature to be reused for different recipients
            let message = amount.to_le_bytes();
            if !self.verify_signature(&from, &message, &signature) {
                return Err("Invalid signature");
            }
            
            // Process transfer
            self.accounts.get_mut(&from).unwrap().balance -= amount;
            
            // Create to_account if it doesn't exist
            if !self.accounts.contains_key(&to) {
                self.accounts.insert(to, WalletAccount {
                    owner: to,
                    balance: 0,
                });
            }
            
            self.accounts.get_mut(&to).unwrap().balance += amount;
            
            Ok(())
        }
        
        /// Vulnerable signature verification (simplified for example)
        fn verify_signature(&self, pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            // Simplified mock verification - in a real situation this would use proper crypto
            // This is just for demonstration
            true // Always returns true for simplicity in this example
        }
    }
}

/// Module containing a secure implementation
pub mod secure {
    use std::collections::HashMap;
    
    /// A wallet program with secure signature verification
    pub struct WalletProgram {
        pub accounts: HashMap<[u8; 32], WalletAccount>,
        pub nonces: HashMap<[u8; 32], u64>, // Store nonces for replay protection
    }
    
    /// Wallet account structure
    pub struct WalletAccount {
        pub owner: [u8; 32],
        pub balance: u64,
    }
    
    impl WalletProgram {
        /// Create a new wallet program
        pub fn new() -> Self {
            Self {
                accounts: HashMap::new(),
                nonces: HashMap::new(),
            }
        }
        
        /// Transfer with secure signature verification
        pub fn transfer(&mut self, 
                        from: [u8; 32], 
                        to: [u8; 32], 
                        amount: u64, 
                        nonce: u64,
                        signature: [u8; 64]) -> Result<(), &'static str> {
            // Get the account or return an error
            let from_account = self.accounts.get(&from)
                .ok_or("Account not found")?;
            
            // Check balance
            if from_account.balance < amount {
                return Err("Insufficient funds");
            }
            
            // Check nonce to prevent replay attacks
            let current_nonce = self.nonces.get(&from).copied().unwrap_or(0);
            if nonce <= current_nonce {
                return Err("Invalid nonce - potential replay attack");
            }
            
            // SECURE: Include all relevant transaction data in the message to be signed
            // This includes sender, recipient, amount, and nonce
            let mut message = Vec::with_capacity(32 + 32 + 8 + 8);
            message.extend_from_slice(&from);
            message.extend_from_slice(&to);
            message.extend_from_slice(&amount.to_le_bytes());
            message.extend_from_slice(&nonce.to_le_bytes());
            
            if !self.verify_signature(&from, &message, &signature) {
                return Err("Invalid signature");
            }
            
            // Update nonce first to prevent reentrancy
            self.nonces.insert(from, nonce);
            
            // Process transfer
            self.accounts.get_mut(&from).unwrap().balance -= amount;
            
            // Create to_account if it doesn't exist
            if !self.accounts.contains_key(&to) {
                self.accounts.insert(to, WalletAccount {
                    owner: to,
                    balance: 0,
                });
            }
            
            self.accounts.get_mut(&to).unwrap().balance += amount;
            
            Ok(())
        }
        
        /// Secure signature verification (simplified for example)
        fn verify_signature(&self, pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            // Simplified mock verification - in a real situation this would use proper crypto
            // This is just for demonstration
            true // Always returns true for simplicity in this example
        }
    }
}
