//! Utility functions and structures for demonstrating vulnerabilities
//!
//! This module contains helper code used across the vulnerability examples,
//! including mock blockchain environments, account structures, and testing utilities.

use std::collections::HashMap;

/// Mock account structure for examples
#[derive(Debug, Clone)]
pub struct Account {
    pub address: [u8; 32],
    pub balance: u64,
    pub owner: Option<[u8; 32]>,
    pub data: Vec<u8>,
    pub executable: bool,
}

impl Account {
    pub fn new(address: [u8; 32]) -> Self {
        Self {
            address,
            balance: 0,
            owner: None,
            data: Vec::new(),
            executable: false,
        }
    }
    
    pub fn with_balance(mut self, balance: u64) -> Self {
        self.balance = balance;
        self
    }
}

/// Mock blockchain environment for examples
#[derive(Debug, Default)]
pub struct MockBlockchain {
    accounts: HashMap<[u8; 32], Account>,
    current_block: u64,
    timestamp: u64,
}

impl MockBlockchain {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            current_block: 1,
            timestamp: 1621500000, // Example timestamp
        }
    }
    
    pub fn add_account(&mut self, account: Account) {
        self.accounts.insert(account.address, account);
    }
    
    pub fn get_account(&self, address: &[u8; 32]) -> Option<&Account> {
        self.accounts.get(address)
    }
    
    pub fn get_account_mut(&mut self, address: &[u8; 32]) -> Option<&mut Account> {
        self.accounts.get_mut(address)
    }
    
    pub fn advance_block(&mut self) {
        self.current_block += 1;
        self.timestamp += 1; // Simplified: 1 second per block
    }
}

/// Generate a pseudorandom account address (for examples only)
pub fn generate_address() -> [u8; 32] {
    let mut addr = [0u8; 32];
    // Very simple deterministic "random" for examples
    for i in 0..32 {
        addr[i] = (i * 7) as u8;
    }
    addr
}

/// Check if an address has a specific privilege in a mock access control system
pub fn has_privilege(address: &[u8; 32], privilege: &str) -> bool {
    // For example purposes, we're just checking if any byte matches the first char of privilege
    let first_byte = privilege.bytes().next().unwrap_or(0);
    address.iter().any(|&b| b == first_byte)
}

/// Utilities for formatting/printing
pub mod display {
    /// Format an address as a hexadecimal string
    pub fn format_address(address: &[u8; 32]) -> String {
        format!("0x{}", hex::encode(address))
    }
    
    /// Format an amount with token symbol
    pub fn format_amount(amount: u64, symbol: &str) -> String {
        format!("{} {}", amount, symbol)
    }
}

#[cfg(feature = "mock-runtime")]
pub mod runtime {
    use super::*;
    
    /// Mock runtime environment
    pub struct Runtime {
        pub blockchain: MockBlockchain,
        pub current_caller: [u8; 32],
    }
    
    impl Runtime {
        pub fn new() -> Self {
            Self {
                blockchain: MockBlockchain::new(),
                current_caller: [0u8; 32],
            }
        }
        
        pub fn with_caller(mut self, caller: [u8; 32]) -> Self {
            self.current_caller = caller;
            self
        }
    }
}
