//! # Storage Management Vulnerability
//!
//! Storage management vulnerabilities occur when smart contracts mishandle blockchain storage,
//! leading to data corruption, unexpected behavior, or excessive resource consumption.
//!
//! In Rust smart contracts, these vulnerabilities manifest through:
//! - Improper account data validation
//! - Memory safety issues specific to blockchain environments
//! - Inefficient storage patterns leading to high gas costs
//! - Data corruption due to improper serialization/deserialization

use crate::vulnerabilities::Vulnerability;
use crate::utils::{Account, MockBlockchain};

/// Represents a storage management vulnerability example
pub struct StorageManagementVulnerability;

impl Vulnerability for StorageManagementVulnerability {
    fn name(&self) -> &'static str {
        "Storage Management Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract improperly manages on-chain storage, leading to data corruption, \
        inefficient resource usage, or unexpected behavior. This includes problems with serialization, \
        account management, and memory safety issues specific to blockchain environments."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "CosmWasm"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable Solana program with storage management issues
        pub fn process_instruction(
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            instruction_data: &[u8],
        ) -> ProgramResult {
            let accounts_iter = &mut accounts.iter();
            let account = next_account_info(accounts_iter)?;
            
            // VULNERABILITY: No size validation before deserializing
            // If the account data is smaller than expected, this will panic
            let mut data = account.try_borrow_mut_data()?;
            
            // VULNERABILITY: No ownership check
            // Should verify account.owner == program_id
            
            // Deserialize account data
            let mut state = State::try_from_slice(&data)?;
            
            // Process based on instruction
            let instruction = instruction_data[0];
            match instruction {
                0 => {
                    // Increment counter
                    state.counter += 1;
                }
                1 => {
                    // VULNERABILITY: No bounds checking when extending storage
                    // If we try to add more items than the account can hold, it will fail
                    let new_value = instruction_data[1..].try_into().unwrap();
                    state.values.push(new_value);
                }
                _ => return Err(ProgramError::InvalidInstructionData),
            }
            
            // VULNERABILITY: No error handling for serialization
            // If serialization fails, we may leave the account in a corrupted state
            state.serialize(&mut *data)?;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Check for proper account size validation before operations",
            "Verify account ownership checks are implemented correctly",
            "Look for proper error handling during serialization/deserialization",
            "Analyze storage patterns for efficiency and cost",
            "Check for bounds validation when extending dynamic data structures",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Always validate account size before operations",
            "Implement comprehensive ownership checks",
            "Use robust error handling for all serialization/deserialization",
            "Design efficient storage patterns to minimize costs",
            "Implement proper bounds checking for dynamic data structures",
        ]
    }
}

/// Module containing a vulnerable implementation
pub mod vulnerable {
    use std::collections::HashMap;
    
    /// A simplified program with storage management issues
    pub struct Program {
        // Simulated blockchain accounts
        pub accounts: HashMap<[u8; 32], AccountData>,
    }
    
    /// Account data structure
    pub struct AccountData {
        pub owner: [u8; 32],
        pub data: Vec<u8>,
    }
    
    /// State structure (would be serialized/deserialized in a real contract)
    #[derive(Clone)]
    pub struct State {
        pub counter: u64,
        pub values: Vec<u64>,
    }
    
    impl Program {
        /// Create a new program
        pub fn new() -> Self {
            Self {
                accounts: HashMap::new(),
            }
        }
        
        /// Initialize an account
        pub fn initialize_account(&mut self, account_id: [u8; 32], owner: [u8; 32]) -> Result<(), &'static str> {
            // Create a new account with initial state
            let state = State {
                counter: 0,
                values: Vec::new(),
            };
            
            // Serialize state (simplified for example)
            let data = self.serialize_state(&state)?;
            
            // Store the account
            self.accounts.insert(account_id, AccountData {
                owner,
                data,
            });
            
            Ok(())
        }
        
        /// Process an instruction with vulnerable storage management
        pub fn process_instruction(&mut self, 
                                 program_id: [u8; 32],
                                 account_id: [u8; 32], 
                                 instruction: u8, 
                                 instruction_data: &[u8]) -> Result<(), &'static str> {
            
            // Get the account
            let account = self.accounts.get_mut(&account_id)
                .ok_or("Account not found")?;
            
            // VULNERABILITY: No ownership check
            // Should verify account.owner == program_id
            
            // Deserialize state (simplified for example)
            let mut state = self.deserialize_state(&account.data)?;
            
            // Process based on instruction
            match instruction {
                0 => {
                    // Increment counter
                    state.counter += 1;
                }
                1 => {
                    // VULNERABILITY: No bounds checking or size validation
                    if instruction_data.len() < 8 {
                        return Err("Invalid instruction data");
                    }
                    
                    // Parse value from instruction data
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&instruction_data[0..8]);
                    let value = u64::from_le_bytes(bytes);
                    
                    // Add value to the list
                    state.values.push(value);
                }
                _ => return Err("Invalid instruction"),
            }
            
            // Serialize state (simplified for example)
            let data = self.serialize_state(&state)?;
            
            // VULNERABILITY: No size check before updating account data
            // In a real blockchain, accounts have fixed sizes and this could fail
            account.data = data;
            
            Ok(())
        }
        
        /// Simplified serialization (in a real contract, this would use borsh or another serializer)
        fn serialize_state(&self, state: &State) -> Result<Vec<u8>, &'static str> {
            let mut data = Vec::new();
            
            // Serialize counter
            data.extend_from_slice(&state.counter.to_le_bytes());
            
            // Serialize values length
            let values_len = state.values.len() as u64;
            data.extend_from_slice(&values_len.to_le_bytes());
            
            // Serialize each value
            for value in &state.values {
                data.extend_from_slice(&value.to_le_bytes());
            }
            
            Ok(data)
        }
        
        /// Simplified deserialization
        fn deserialize_state(&self, data: &[u8]) -> Result<State, &'static str> {
            if data.len() < 16 {
                return Err("Data too small to deserialize");
            }
            
            // Deserialize counter
            let mut counter_bytes = [0u8; 8];
            counter_bytes.copy_from_slice(&data[0..8]);
            let counter = u64::from_le_bytes(counter_bytes);
            
            // Deserialize values length
            let mut values_len_bytes = [0u8; 8];
            values_len_bytes.copy_from_slice(&data[8..16]);
            let values_len = u64::from_le_bytes(values_len_bytes) as usize;
            
            // VULNERABILITY: No bounds checking
            // Should verify there's enough data for all values
            
            // Deserialize values
            let mut values = Vec::with_capacity(values_len);
            for i in 0..values_len {
                let start = 16 + i * 8;
                if start + 8 > data.len() {
                    return Err("Data too small to deserialize all values");
                }
                
                let mut value_bytes = [0u8; 8];
                value_bytes.copy_from_slice(&data[start..start+8]);
                values.push(u64::from_le_bytes(value_bytes));
            }
            
            Ok(State {
                counter,
                values,
            })
        }
    }
}

/// Module containing a secure implementation
pub mod secure {
    use std::collections::HashMap;
    
    /// A program with proper storage management
    pub struct Program {
        // Simulated blockchain accounts
        pub accounts: HashMap<[u8; 32], AccountData>,
    }
    
    /// Account data structure
    pub struct AccountData {
        pub owner: [u8; 32],
        pub data: Vec<u8>,
        pub size: usize, // Fixed size of the account (simulating blockchain constraints)
    }
    
    /// State structure (would be serialized/deserialized in a real contract)
    #[derive(Clone)]
    pub struct State {
        pub counter: u64,
        pub values: Vec<u64>,
    }
    
    impl Program {
        /// Create a new program
        pub fn new() -> Self {
            Self {
                accounts: HashMap::new(),
            }
        }
        
        /// Initialize an account with a specified size
        pub fn initialize_account(&mut self, account_id: [u8; 32], owner: [u8; 32], size: usize) -> Result<(), &'static str> {
            // Create a new account with initial state
            let state = State {
                counter: 0,
                values: Vec::new(),
            };
            
            // Serialize state
            let data = self.serialize_state(&state)?;
            
            // Check if the allocated size is sufficient
            if data.len() > size {
                return Err("Account size too small for initial state");
            }
            
            // Store the account with fixed size
            self.accounts.insert(account_id, AccountData {
                owner,
                data,
                size,
            });
            
            Ok(())
        }
        
        /// Process an instruction with secure storage management
        pub fn process_instruction(&mut self, 
                                 program_id: [u8; 32],
                                 account_id: [u8; 32], 
                                 instruction: u8, 
                                 instruction_data: &[u8]) -> Result<(), &'static str> {
            
            // Get the account
            let account = self.accounts.get_mut(&account_id)
                .ok_or("Account not found")?;
            
            // SECURE: Verify account ownership
            if account.owner != program_id {
                return Err("Account not owned by this program");
            }
            
            // Deserialize state
            let mut state = self.deserialize_state(&account.data)?;
            
            // Process based on instruction
            match instruction {
                0 => {
                    // Increment counter
                    state.counter += 1;
                }
                1 => {
                    // SECURE: Validate instruction data
                    if instruction_data.len() < 8 {
                        return Err("Invalid instruction data");
                    }
                    
                    // Parse value from instruction data
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&instruction_data[0..8]);
                    let value = u64::from_le_bytes(bytes);
                    
                    // SECURE: Check if adding a new value would exceed account size
                    let current_values_size = state.values.len() * 8;
                    let new_size_estimate = 16 + ((state.values.len() + 1) * 8); // 8 for counter, 8 for length, 8 for each value
                    
                    if new_size_estimate > account.size {
                        return Err("Account capacity exceeded");
                    }
                    
                    // Add value to the list
                    state.values.push(value);
                }
                _ => return Err("Invalid instruction"),
            }
            
            // Serialize state
            let new_data = self.serialize_state(&state)?;
            
            // SECURE: Validate the new data will fit in the account's allocated size
            if new_data.len() > account.size {
                return Err("Operation would exceed account size");
            }
            
            // Update account data
            account.data = new_data;
            
            Ok(())
        }
        
        /// Serialization with proper error handling
        fn serialize_state(&self, state: &State) -> Result<Vec<u8>, &'static str> {
            let mut data = Vec::new();
            
            // Serialize counter
            data.extend_from_slice(&state.counter.to_le_bytes());
            
            // Serialize values length
            let values_len = state.values.len() as u64;
            data.extend_from_slice(&values_len.to_le_bytes());
            
            // Serialize each value
            for value in &state.values {
                data.extend_from_slice(&value.to_le_bytes());
            }
            
            Ok(data)
        }
        
        /// Deserialization with proper bounds checking and error handling
        fn deserialize_state(&self, data: &[u8]) -> Result<State, &'static str> {
            // SECURE: Validate minimum data size
            if data.len() < 16 {
                return Err("Data too small to deserialize");
            }
            
            // Deserialize counter
            let mut counter_bytes = [0u8; 8];
            counter_bytes.copy_from_slice(&data[0..8]);
            let counter = u64::from_le_bytes(counter_bytes);
            
            // Deserialize values length
            let mut values_len_bytes = [0u8; 8];
            values_len_bytes.copy_from_slice(&data[8..16]);
            let values_len = u64::from_le_bytes(values_len_bytes) as usize;
            
            // SECURE: Validate there's enough data for all values
            if data.len() < 16 + (values_len * 8) {
                return Err("Data too small to deserialize all values");
            }
            
            // Deserialize values
            let mut values = Vec::with_capacity(values_len);
            for i in 0..values_len {
                let start = 16 + i * 8;
                
                let mut value_bytes = [0u8; 8];
                value_bytes.copy_from_slice(&data[start..start+8]);
                values.push(u64::from_le_bytes(value_bytes));
            }
            
            Ok(State {
                counter,
                values,
            })
        }
    }
}
