//! # Random Number Manipulation Vulnerability
//!
//! Random number manipulation vulnerabilities occur when a smart contract
//! relies on sources of randomness that can be predicted or manipulated by
//! attackers. This can lead to exploitation of games, lotteries, NFT minting,
//! or any other functionality that requires unpredictable random values.
//!
//! In blockchain environments, achieving true randomness is challenging due to
//! the deterministic nature of transaction processing.

use crate::vulnerabilities::Vulnerability;

/// Represents a random number manipulation vulnerability example
pub struct RandomManipulationVulnerability;

impl Vulnerability for RandomManipulationVulnerability {
    fn name(&self) -> &'static str {
        "Random Number Manipulation Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract relies on sources of randomness that can be \
        predicted or manipulated by attackers. This can lead to exploitation of games, \
        lotteries, NFT minting, or any other functionality that requires unpredictable random values."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All blockchain platforms"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function with predictable randomness
        pub fn select_winner(ctx: Context<SelectWinner>) -> Result<()> {
            let lottery = &mut ctx.accounts.lottery;
            
            // VULNERABILITY: Using block timestamp as randomness source
            let current_timestamp = Clock::get()?.unix_timestamp as u64;
            
            // VULNERABILITY: Predictable hash calculation
            let seed = lottery.ticket_count.to_le_bytes()
                .iter()
                .chain(current_timestamp.to_le_bytes().iter())
                .copied()
                .collect::<Vec<u8>>();
                
            let hash = hash::hash(&seed);
            
            // Select winner based on this hash
            let winner_index = (u64::from_le_bytes(hash.to_bytes()[0..8].try_into().unwrap())) % lottery.ticket_count;
            lottery.winner = lottery.participants[winner_index as usize];
            
            Ok(())
        }
        
        // Vulnerable function for NFT attribute generation
        pub fn mint_random_nft(ctx: Context<MintNFT>) -> Result<()> {
            let mint_data = &mut ctx.accounts.mint_data;
            
            // VULNERABILITY: Using transaction signature as randomness source
            // This can be manipulated by miners/validators or predicted in advance
            let signature = ctx.accounts.authority.key().to_bytes();
            
            // Generate "random" attributes
            let rarity = (signature[0] % 100) + 1; // 1-100 rarity
            let strength = (signature[1] % 50) + 1; // 1-50 strength
            let agility = (signature[2] % 50) + 1; // 1-50 agility
            
            // Set NFT attributes
            mint_data.rarity = rarity;
            mint_data.strength = strength;
            mint_data.agility = agility;
            
            // Mint NFT
            // ...minting logic...
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Identify all sources of randomness in the contract",
            "Check if randomness sources are predictable (block data, timestamps)",
            "Look for randomness derived from user-controllable inputs",
            "Verify if randomness can be manipulated by validators/miners",
            "Check if pseudo-random number generators (PRNGs) are properly seeded",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Use a verifiable random function (VRF) service where available",
            "Implement commit-reveal schemes for randomness",
            "Combine multiple sources of entropy that cannot all be controlled",
            "Consider using off-chain oracles for randomness when appropriate",
            "For low-security needs, use cryptographic hashing of multiple inputs",
        ]
    }
}

/// Example of vulnerable code with manipulable randomness
pub mod vulnerable {
    use std::collections::HashMap;
    
    #[derive(Debug, Clone)]
    pub struct Lottery {
        pub id: u64,
        pub participants: Vec<[u8; 32]>,
        pub ticket_count: u64,
        pub winner: Option<[u8; 32]>,
        pub prize_amount: u64,
        pub is_complete: bool,
    }
    
    #[derive(Debug, Clone)]
    pub struct NFTAttributes {
        pub rarity: u8,
        pub strength: u8,
        pub agility: u8,
        pub intelligence: u8,
        pub luck: u8,
    }
    
    pub struct GamePlatform {
        pub lotteries: HashMap<u64, Lottery>,
        pub nfts: HashMap<u64, NFTAttributes>,
        pub next_lottery_id: u64,
        pub next_nft_id: u64,
        pub block_number: u64,
        pub block_timestamp: u64,
    }
    
    impl GamePlatform {
        pub fn new() -> Self {
            Self {
                lotteries: HashMap::new(),
                nfts: HashMap::new(),
                next_lottery_id: 1,
                next_nft_id: 1,
                block_number: 1,
                block_timestamp: 1_650_000_000, // Some arbitrary starting timestamp
            }
        }
        
        /// Vulnerable function with predictable lottery winner selection
        pub fn select_lottery_winner(&mut self, lottery_id: u64) -> Result<[u8; 32], &'static str> {
            let lottery = match self.lotteries.get_mut(&lottery_id) {
                Some(lottery) => lottery,
                None => return Err("Lottery not found"),
            };
            
            if lottery.is_complete {
                return Err("Lottery already completed");
            }
            
            if lottery.participants.is_empty() {
                return Err("No participants in lottery");
            }
            
            // VULNERABILITY: Using block data as randomness source
            // In a real blockchain, this data can be predicted or manipulated
            let random_seed = self.block_timestamp ^ self.block_number;
            
            // Select winner
            let winner_index = random_seed % lottery.participants.len() as u64;
            let winner = lottery.participants[winner_index as usize];
            
            lottery.winner = Some(winner);
            lottery.is_complete = true;
            
            Ok(winner)
        }
        
        /// Vulnerable function for generating random NFT attributes
        pub fn mint_random_nft(&mut self, minter: [u8; 32], tx_hash: [u8; 32]) -> Result<u64, &'static str> {
            // VULNERABILITY: Using transaction hash (partially controlled by user)
            // and block data for randomness
            
            // Create a "random" seed from transaction hash and block data
            let mut random_bytes = [0u8; 8];
            for i in 0..8 {
                random_bytes[i] = tx_hash[i] ^ (self.block_timestamp as u8) ^ (self.block_number as u8);
            }
            
            // Convert to a u64
            let mut seed = 0u64;
            for i in 0..8 {
                seed = (seed << 8) | random_bytes[i] as u64;
            }
            
            // Generate attributes
            let attributes = NFTAttributes {
                rarity: ((seed % 100) + 1) as u8,
                strength: (((seed >> 8) % 50) + 1) as u8,
                agility: (((seed >> 16) % 50) + 1) as u8,
                intelligence: (((seed >> 24) % 50) + 1) as u8,
                luck: (((seed >> 32) % 50) + 1) as u8,
            };
            
            // Store NFT
            let nft_id = self.next_nft_id;
            self.next_nft_id += 1;
            self.nfts.insert(nft_id, attributes);
            
            Ok(nft_id)
        }
        
        /// Vulnerable dice roll function
        pub fn roll_dice(&mut self, player: [u8; 32]) -> u8 {
            // VULNERABILITY: Using simple block data for randomness
            // A miner/validator could manipulate the outcome
            
            // Create a "random" value from block timestamp and player address
            let random_value = (self.block_timestamp ^ (player[0] as u64)) % 6;
            
            // Return a value from 1 to 6
            (random_value + 1) as u8
        }
        
        /// Helper to simulate new block (for testing)
        pub fn advance_block(&mut self) {
            self.block_number += 1;
            self.block_timestamp += 12; // Assume 12 second block time
        }
    }
}

/// Example of secure code with better randomness generation
pub mod secure {
    use std::collections::HashMap;
    
    #[derive(Debug, Clone)]
    pub struct Lottery {
        pub id: u64,
        pub participants: Vec<[u8; 32]>,
        pub ticket_count: u64,
        pub winner: Option<[u8; 32]>,
        pub prize_amount: u64,
        pub is_complete: bool,
        pub commit_hash: Option<[u8; 32]>,
        pub reveal_deadline: Option<u64>,
    }
    
    #[derive(Debug, Clone)]
    pub struct NFTAttributes {
        pub rarity: u8,
        pub strength: u8,
        pub agility: u8,
        pub intelligence: u8,
        pub luck: u8,
    }
    
    #[derive(Debug, Clone)]
    pub struct CommitReveal {
        pub committer: [u8; 32],
        pub commit_hash: [u8; 32],
        pub revealed_value: Option<[u8; 32]>,
        pub commit_block: u64,
        pub reveal_deadline: u64,
    }
    
    #[derive(Debug, Clone)]
    pub struct RandomnessRequest {
        pub id: u64,
        pub requester: [u8; 32],
        pub fulfilled: bool,
        pub random_value: Option<[u8; 32]>,
        pub callback_data: Vec<u8>,
    }
    
    pub struct GamePlatform {
        pub lotteries: HashMap<u64, Lottery>,
        pub nfts: HashMap<u64, NFTAttributes>,
        pub next_lottery_id: u64,
        pub next_nft_id: u64,
        pub block_number: u64,
        pub block_timestamp: u64,
        pub commit_reveals: HashMap<[u8; 32], CommitReveal>,
        pub randomness_requests: HashMap<u64, RandomnessRequest>,
        pub next_request_id: u64,
        pub vrf_public_key: [u8; 32], // Mock VRF key
    }
    
    impl GamePlatform {
        pub fn new() -> Self {
            Self {
                lotteries: HashMap::new(),
                nfts: HashMap::new(),
                next_lottery_id: 1,
                next_nft_id: 1,
                block_number: 1,
                block_timestamp: 1_650_000_000, // Some arbitrary starting timestamp
                commit_reveals: HashMap::new(),
                randomness_requests: HashMap::new(),
                next_request_id: 1,
                vrf_public_key: [0xaa; 32], // Mock VRF key
            }
        }
        
        /// Secure lottery with commit-reveal approach: Step 1 - Commit
        pub fn commit_lottery_seed(&mut self, lottery_id: u64, committer: [u8; 32], commit_hash: [u8; 32]) -> Result<(), &'static str> {
            let lottery = match self.lotteries.get_mut(&lottery_id) {
                Some(lottery) => lottery,
                None => return Err("Lottery not found"),
            };
            
            if lottery.is_complete {
                return Err("Lottery already completed");
            }
            
            if lottery.participants.is_empty() {
                return Err("No participants in lottery");
            }
            
            // Store commit hash and set reveal deadline
            lottery.commit_hash = Some(commit_hash);
            lottery.reveal_deadline = Some(self.block_number + 10); // 10 blocks to reveal
            
            // Store commit-reveal data
            let commit_reveal = CommitReveal {
                committer,
                commit_hash,
                revealed_value: None,
                commit_block: self.block_number,
                reveal_deadline: self.block_number + 10,
            };
            
            self.commit_reveals.insert(commit_hash, commit_reveal);
            
            Ok(())
        }
        
        /// Secure lottery with commit-reveal approach: Step 2 - Reveal
        pub fn reveal_lottery_seed(&mut self, lottery_id: u64, seed: [u8; 32], salt: [u8; 32]) -> Result<[u8; 32], &'static str> {
            let lottery = match self.lotteries.get_mut(&lottery_id) {
                Some(lottery) => lottery,
                None => return Err("Lottery not found"),
            };
            
            if lottery.is_complete {
                return Err("Lottery already completed");
            }
            
            let commit_hash = match lottery.commit_hash {
                Some(hash) => hash,
                None => return Err("No commit found for this lottery"),
            };
            
            // Check if reveal deadline has passed
            if let Some(deadline) = lottery.reveal_deadline {
                if self.block_number > deadline {
                    return Err("Reveal deadline has passed");
                }
            }
            
            // Verify commit matches reveal
            // In a real implementation, this would hash the seed+salt and verify it matches commit_hash
            let commit_reveal = match self.commit_reveals.get_mut(&commit_hash) {
                Some(cr) => cr,
                None => return Err("Commit not found"),
            };
            
            // Update commit reveal with the revealed value
            commit_reveal.revealed_value = Some(seed);
            
            // Generate randomness by combining seed with chain data
            let chain_data = self.block_timestamp.to_be_bytes();
            
            // Combine seed with blockchain data
            let mut combined = [0u8; 32];
            for i in 0..32 {
                combined[i] = seed[i] ^ (if i < 8 { chain_data[i] } else { 0 });
            }
            
            // Select winner
            let winner_index = (combined[0] as u64 % lottery.participants.len() as u64) as usize;
            let winner = lottery.participants[winner_index];
            
            lottery.winner = Some(winner);
            lottery.is_complete = true;
            
            Ok(winner)
        }
        
        /// Secure NFT with VRF (mocking external VRF behavior)
        pub fn request_random_nft(&mut self, minter: [u8; 32]) -> Result<u64, &'static str> {
            // Create a randomness request that will be fulfilled by VRF
            let request_id = self.next_request_id;
            self.next_request_id += 1;
            
            let request = RandomnessRequest {
                id: request_id,
                requester: minter,
                fulfilled: false,
                random_value: None,
                callback_data: Vec::new(), // In a real implementation, this would store the NFT mint data
            };
            
            self.randomness_requests.insert(request_id, request);
            
            // In a real implementation, this would emit an event for the VRF to process
            
            Ok(request_id)
        }
        
        /// Callback for VRF to fulfill randomness (would be called by VRF oracle)
        pub fn fulfill_randomness(&mut self, request_id: u64, random_value: [u8; 32], proof: [u8; 64]) -> Result<u64, &'static str> {
            // In a real implementation, we would verify the proof against our VRF public key
            
            let request = match self.randomness_requests.get_mut(&request_id) {
                Some(req) => req,
                None => return Err("Request not found"),
            };
            
            if request.fulfilled {
                return Err("Request already fulfilled");
            }
            
            // Update request
            request.fulfilled = true;
            request.random_value = Some(random_value);
            
            // Generate NFT using verifiable randomness
            let attributes = NFTAttributes {
                rarity: ((random_value[0] as u16 * 100 / 255) + 1) as u8,
                strength: ((random_value[1] as u16 * 50 / 255) + 1) as u8,
                agility: ((random_value[2] as u16 * 50 / 255) + 1) as u8,
                intelligence: ((random_value[3] as u16 * 50 / 255) + 1) as u8,
                luck: ((random_value[4] as u16 * 50 / 255) + 1) as u8,
            };
            
            // Store NFT
            let nft_id = self.next_nft_id;
            self.next_nft_id += 1;
            self.nfts.insert(nft_id, attributes);
            
            Ok(nft_id)
        }
        
        /// Secure dice roll using multiple sources of entropy 
        pub fn roll_dice(&mut self, player: [u8; 32], player_seed: [u8; 32]) -> Result<u8, &'static str> {
            // Combine multiple sources of entropy:
            // 1. Block data (still vulnerable but harder to exploit in combination)
            // 2. Player address (known in advance but fixed)
            // 3. Player provided seed (can be manipulated but combined with other sources)
            // 4. Previous block hash (would be available in a real blockchain)
            
            // Mock previous block hash by hashing the current block number
            let mock_prev_block_hash = {
                let mut hash = [0u8; 32];
                let block_bytes = self.block_number.to_be_bytes();
                for i in 0..8 {
                    hash[i] = block_bytes[i];
                }
                hash
            };
            
            // Combine sources of entropy
            let mut combined = [0u8; 32];
            
            // XOR all sources together
            for i in 0..32 {
                combined[i] = player[i % player.len()] ^ 
                             player_seed[i % player_seed.len()] ^ 
                             mock_prev_block_hash[i];
            }
            
            // Add block timestamp influence
            let timestamp_bytes = self.block_timestamp.to_be_bytes();
            for i in 0..8 {
                combined[i] ^= timestamp_bytes[i];
            }
            
            // Take first byte and map to 1-6
            let dice_value = (combined[0] % 6) + 1;
            
            Ok(dice_value)
        }
        
        /// Helper to simulate new block (for testing)
        pub fn advance_block(&mut self) {
            self.block_number += 1;
            self.block_timestamp += 12; // Assume 12 second block time
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_predictable_randomness() {
        let mut platform = vulnerable::GamePlatform::new();
        
        // Create a lottery
        let lottery_id = 1;
        platform.lotteries.insert(lottery_id, vulnerable::Lottery {
            id: lottery_id,
            participants: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]],
            ticket_count: 5,
            winner: None,
            prize_amount: 100,
            is_complete: false,
        });
        
        // Set a specific block state
        platform.block_number = 12345;
        platform.block_timestamp = 1_650_000_000;
        
        // Select winner - this is predictable if you know the block data
        let winner1 = platform.select_lottery_winner(lottery_id).unwrap();
        
        // Reset lottery
        platform.lotteries.get_mut(&lottery_id).unwrap().is_complete = false;
        platform.lotteries.get_mut(&lottery_id).unwrap().winner = None;
        
        // With the same block data, we get the same winner
        let winner2 = platform.select_lottery_winner(lottery_id).unwrap();
        assert_eq!(winner1, winner2);
        
        // Now test dice rolling
        let player = [10u8; 32];
        
        // Roll dice with fixed block data - predictable
        let roll1 = platform.roll_dice(player);
        let roll2 = platform.roll_dice(player);
        
        // Same block, same player = same result
        assert_eq!(roll1, roll2);
    }
    
    #[test]
    fn test_secure_randomness_generation() {
        let mut platform = secure::GamePlatform::new();
        
        // Create a lottery
        let lottery_id = 1;
        platform.lotteries.insert(lottery_id, secure::Lottery {
            id: lottery_id,
            participants: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]],
            ticket_count: 5,
            winner: None,
            prize_amount: 100,
            is_complete: false,
            commit_hash: None,
            reveal_deadline: None,
        });
        
        // Create commit hash (in reality, this would be hash(seed + salt))
        let commit_hash = [0xbb; 32];
        let committer = [0xcc; 32];
        
        // Commit to a random seed
        let result = platform.commit_lottery_seed(lottery_id, committer, commit_hash);
        assert!(result.is_ok());
        
        // Advance a few blocks
        platform.advance_block();
        platform.advance_block();
        
        // Reveal the seed and select winner
        let seed = [0xdd; 32];
        let salt = [0xee; 32];
        let winner = platform.reveal_lottery_seed(lottery_id, seed, salt);
        assert!(winner.is_ok());
        
        // Test VRF-based NFT minting
        let minter = [0xff; 32];
        let request_id = platform.request_random_nft(minter).unwrap();
        
        // Simulate VRF response
        let random_value = [0x12; 32];
        let proof = [0x34; 64];
        
        let nft_id = platform.fulfill_randomness(request_id, random_value, proof).unwrap();
        
        // Verify NFT was created with attributes derived from the random value
        let nft = platform.nfts.get(&nft_id).unwrap();
        assert_eq!(nft.rarity, ((random_value[0] as u16 * 100 / 255) + 1) as u8);
        
        // Test secure dice roll
        let player = [0xaa; 32];
        let player_seed = [0xbb; 32];
        
        let roll = platform.roll_dice(player, player_seed).unwrap();
        assert!(roll >= 1 && roll <= 6);
        
        // Even with the same player and block, a different seed gives different results
        let different_seed = [0xcc; 32];
        let different_roll = platform.roll_dice(player, different_seed).unwrap();
        
        // Not guaranteed to be different, but highly likely
        // In reality, with proper hashing, this would be much more robust
    }
}
