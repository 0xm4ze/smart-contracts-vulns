//! # Logic Error Vulnerability
//!
//! Logic error vulnerabilities occur when a smart contract's business logic
//! is flawed, causing unexpected behavior or allowing exploitation even when
//! the code executes as written. These errors are often subtle and specific
//! to the contract's intended functionality.
//!
//! In Rust smart contracts, logic errors can manifest as incorrect state transitions,
//! faulty validation, or improper handling of edge cases.

use crate::vulnerabilities::Vulnerability;

/// Represents a logic error vulnerability example
pub struct LogicErrorVulnerability;

impl Vulnerability for LogicErrorVulnerability {
    fn name(&self) -> &'static str {
        "Logic Error Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract's business logic is flawed, causing unexpected \
        behavior or allowing exploitation even when the code executes as written. \
        These errors are often subtle and specific to the contract's intended functionality."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All Rust-based contracts"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function with incorrect business logic
        pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
            let user = &ctx.accounts.user;
            let mut rewards_account = &mut ctx.accounts.rewards_account;
            
            // VULNERABILITY: Incorrect reward calculation
            // This only accounts for the current stake amount and time delta
            // but doesn't reset the last_claim_time
            let current_time = Clock::get()?.unix_timestamp as u64;
            let time_delta = current_time - user.last_claim_time;
            
            // Calculate rewards
            let reward_rate = 100; // Example: 100 tokens per day per staked token
            let reward_amount = user.staked_amount * reward_rate * time_delta / 86400;
            
            // Transfer rewards
            rewards_account.amount -= reward_amount;
            user.reward_balance += reward_amount;
            
            // VULNERABILITY: Missing update to last_claim_time
            // This allows the user to claim multiple times for the same period
            
            Ok(())
        }
        
        // Vulnerable function with state machine flaw
        pub fn finalize_auction(ctx: Context<FinalizeAuction>) -> Result<()> {
            let auction = &mut ctx.accounts.auction;
            
            // VULNERABILITY: Insufficient state validation
            // Only checks if auction is active, but not if it has ended
            if auction.state != AuctionState::Active {
                return Err(ErrorCode::AuctionNotActive.into());
            }
            
            // Get the highest bidder
            let highest_bidder = auction.highest_bidder.ok_or(ErrorCode::NoBids)?;
            let highest_bid = auction.highest_bid;
            
            // Transfer assets
            transfer_asset(auction.asset_mint, auction.authority, highest_bidder, 1)?;
            transfer_tokens(auction.payment_mint, highest_bidder, auction.authority, highest_bid)?;
            
            // Update state
            auction.state = AuctionState::Ended;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Review business logic against functional requirements",
            "Model state transitions and verify correct handling of all states",
            "Check for missing or incorrect state updates",
            "Verify mathematical calculations, especially for financial operations",
            "Test with a variety of realistic and edge-case scenarios",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Implement comprehensive state validation",
            "Use state machines with explicit transitions",
            "Add safeguards for critical calculations",
            "Validate business logic with formal verification where possible",
            "Extensively test all possible execution paths",
        ]
    }
}

/// Example of vulnerable code with logic errors
pub mod vulnerable {
    #[derive(Debug, Clone, PartialEq)]
    pub enum AuctionState {
        Initialized,
        Active,
        Ended,
    }
    
    #[derive(Debug, Clone)]
    pub struct Auction {
        pub item_id: u64,
        pub creator: [u8; 32],
        pub start_time: u64,
        pub end_time: u64,
        pub reserve_price: u64,
        pub highest_bid: u64,
        pub highest_bidder: Option<[u8; 32]>,
        pub state: AuctionState,
    }
    
    #[derive(Debug, Clone)]
    pub struct StakingAccount {
        pub owner: [u8; 32],
        pub staked_amount: u64,
        pub reward_balance: u64,
        pub last_claim_time: u64,
    }
    
    pub struct AuctionPlatform {
        pub auctions: std::collections::HashMap<u64, Auction>,
        pub staking_accounts: std::collections::HashMap<[u8; 32], StakingAccount>,
        pub reward_pool: u64,
        pub current_time: u64,
    }
    
    impl AuctionPlatform {
        pub fn new() -> Self {
            Self {
                auctions: std::collections::HashMap::new(),
                staking_accounts: std::collections::HashMap::new(),
                reward_pool: 1_000_000,
                current_time: 0,
            }
        }
        
        /// Vulnerable function with incorrect state transition logic
        pub fn start_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
            let auction = match self.auctions.get_mut(&auction_id) {
                Some(auction) => auction,
                None => return Err("Auction not found"),
            };
            
            // VULNERABILITY: Missing check for current state
            // Should only allow transitions from Initialized to Active
            
            // VULNERABILITY: Missing check if auction has already ended
            if self.current_time >= auction.end_time {
                // Should error here, but doesn't
            }
            
            auction.state = AuctionState::Active;
            
            Ok(())
        }
        
        /// Vulnerable function with incorrect time validation
        pub fn place_bid(&mut self, auction_id: u64, bidder: [u8; 32], bid_amount: u64) -> Result<(), &'static str> {
            let auction = match self.auctions.get_mut(&auction_id) {
                Some(auction) => auction,
                None => return Err("Auction not found"),
            };
            
            // Check if auction is active
            if auction.state != AuctionState::Active {
                return Err("Auction is not active");
            }
            
            // VULNERABILITY: Missing check for auction end time
            // if self.current_time >= auction.end_time { 
            //     return Err("Auction has ended");
            // }
            
            // Check if bid is high enough
            if bid_amount <= auction.highest_bid {
                return Err("Bid too low");
            }
            
            if auction.highest_bid == 0 && bid_amount < auction.reserve_price {
                return Err("Bid below reserve price");
            }
            
            // Update highest bid
            auction.highest_bid = bid_amount;
            auction.highest_bidder = Some(bidder);
            
            Ok(())
        }
        
        /// Vulnerable reward claim function with logic error
        pub fn claim_rewards(&mut self, staker: [u8; 32]) -> Result<u64, &'static str> {
            let account = match self.staking_accounts.get_mut(&staker) {
                Some(account) => account,
                None => return Err("Staking account not found"),
            };
            
            // Calculate time since last claim
            let time_delta = self.current_time - account.last_claim_time;
            
            // VULNERABILITY: Incorrect reward calculation logic
            // This assumes a fixed reward rate regardless of staking pool size
            // and doesn't account for compounding or pro-rated distribution
            let reward_rate = 100; // 100 tokens per day per staked token
            let reward_amount = account.staked_amount * reward_rate * time_delta / 86400;
            
            // Check reward pool
            if reward_amount > self.reward_pool {
                return Err("Insufficient rewards in pool");
            }
            
            // Update balances
            self.reward_pool -= reward_amount;
            account.reward_balance += reward_amount;
            
            // VULNERABILITY: Incorrect update of last claim time
            // This allows claiming multiple times for the same period
            // account.last_claim_time = self.current_time;
            
            Ok(reward_amount)
        }
        
        /// Vulnerable function with incorrect finality logic
        pub fn finalize_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
            let auction = match self.auctions.get_mut(&auction_id) {
                Some(auction) => auction,
                None => return Err("Auction not found"),
            };
            
            // VULNERABILITY: Missing time check
            // Should require auction end_time has passed
            // if self.current_time < auction.end_time {
            //     return Err("Auction still active");
            // }
            
            // VULNERABILITY: Incorrect state transition
            // Only checks if auction is not ended, should be more specific
            if auction.state == AuctionState::Ended {
                return Err("Auction already finalized");
            }
            
            // Check if there's a winning bid
            if auction.highest_bidder.is_none() {
                auction.state = AuctionState::Ended;
                return Err("No bids placed");
            }
            
            // Finalize auction
            auction.state = AuctionState::Ended;
            
            // In a real contract, this would transfer funds and NFT
            
            Ok(())
        }
        
        /// Helper to advance time (for testing)
        pub fn advance_time(&mut self, seconds: u64) {
            self.current_time += seconds;
        }
    }
}

/// Example of secure code with correct business logic
pub mod secure {
    #[derive(Debug, Clone, PartialEq)]
    pub enum AuctionState {
        Initialized,
        Active,
        Ended,
        Finalized,
    }
    
    #[derive(Debug, Clone)]
    pub struct Auction {
        pub item_id: u64,
        pub creator: [u8; 32],
        pub start_time: u64,
        pub end_time: u64,
        pub reserve_price: u64,
        pub highest_bid: u64,
        pub highest_bidder: Option<[u8; 32]>,
        pub state: AuctionState,
    }
    
    #[derive(Debug, Clone)]
    pub struct StakingAccount {
        pub owner: [u8; 32],
        pub staked_amount: u64,
        pub reward_balance: u64,
        pub last_claim_time: u64,
        pub accumulated_rewards: u64,
    }
    
    pub struct AuctionPlatform {
        pub auctions: std::collections::HashMap<u64, Auction>,
        pub staking_accounts: std::collections::HashMap<[u8; 32], StakingAccount>,
        pub reward_pool: u64,
        pub current_time: u64,
        pub total_staked: u64,
    }
    
    impl AuctionPlatform {
        pub fn new() -> Self {
            Self {
                auctions: std::collections::HashMap::new(),
                staking_accounts: std::collections::HashMap::new(),
                reward_pool: 1_000_000,
                current_time: 0,
                total_staked: 0,
            }
        }
        
        /// Secure function with proper state transition logic
        pub fn start_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
            let auction = match self.auctions.get_mut(&auction_id) {
                Some(auction) => auction,
                None => return Err("Auction not found"),
            };
            
            // FIXED: Proper state validation
            if auction.state != AuctionState::Initialized {
                return Err("Auction not in initialized state");
            }
            
            // FIXED: Check auction timing
            if self.current_time < auction.start_time {
                return Err("Auction start time not reached");
            }
            
            if self.current_time >= auction.end_time {
                return Err("Auction end time already passed");
            }
            
            auction.state = AuctionState::Active;
            
            Ok(())
        }
        
        /// Secure function with correct time validation
        pub fn place_bid(&mut self, auction_id: u64, bidder: [u8; 32], bid_amount: u64) -> Result<(), &'static str> {
            let auction = match self.auctions.get_mut(&auction_id) {
                Some(auction) => auction,
                None => return Err("Auction not found"),
            };
            
            // FIXED: Proper state validation
            if auction.state != AuctionState::Active {
                return Err("Auction is not active");
            }
            
            // FIXED: Check if auction has ended by time
            if self.current_time >= auction.end_time {
                auction.state = AuctionState::Ended;
                return Err("Auction has ended");
            }
            
            // Check if bid is high enough
            if auction.highest_bid > 0 && bid_amount <= auction.highest_bid {
                return Err("Bid too low");
            }
            
            if auction.highest_bid == 0 && bid_amount < auction.reserve_price {
                return Err("Bid below reserve price");
            }
            
            // Update highest bid
            auction.highest_bid = bid_amount;
            auction.highest_bidder = Some(bidder);
            
            Ok(())
        }
        
        /// Secure reward claim function with correct logic
        pub fn claim_rewards(&mut self, staker: [u8; 32]) -> Result<u64, &'static str> {
            let account = match self.staking_accounts.get_mut(&staker) {
                Some(account) => account,
                None => return Err("Staking account not found"),
            };
            
            // Calculate time since last claim
            let time_delta = self.current_time - account.last_claim_time;
            
            // No rewards if no time has passed
            if time_delta == 0 {
                return Ok(0);
            }
            
            // FIXED: Improved reward calculation logic
            // Uses a pro-rated approach based on total staked
            let daily_reward_rate = 100; // Base rate
            
            // Calculate rewards based on proportion of total stake
            let reward_amount = if self.total_staked > 0 {
                account.staked_amount * daily_reward_rate * time_delta / 86400
            } else {
                0
            };
            
            // Check reward pool
            if reward_amount > self.reward_pool {
                return Err("Insufficient rewards in pool");
            }
            
            // Update balances
            self.reward_pool -= reward_amount;
            account.reward_balance += reward_amount;
            account.accumulated_rewards += reward_amount;
            
            // FIXED: Always update last claim time
            account.last_claim_time = self.current_time;
            
            Ok(reward_amount)
        }
        
        /// Secure function with correct finality logic
        pub fn finalize_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
            let auction = match self.auctions.get_mut(&auction_id) {
                Some(auction) => auction,
                None => return Err("Auction not found"),
            };
            
            // FIXED: Proper state validation with specific states
            match auction.state {
                AuctionState::Initialized => return Err("Auction not started"),
                AuctionState::Active => {
                    // Check if auction has ended by time
                    if self.current_time < auction.end_time {
                        return Err("Auction still active");
                    }
                },
                AuctionState::Ended => {},
                AuctionState::Finalized => return Err("Auction already finalized"),
            }
            
            // If we reach here and the auction is still Active but has passed end_time,
            // update its state to Ended
            if auction.state == AuctionState::Active && self.current_time >= auction.end_time {
                auction.state = AuctionState::Ended;
            }
            
            // Check if there's a winning bid
            if auction.highest_bidder.is_none() {
                auction.state = AuctionState::Finalized;
                return Err("No bids placed, auction closed without winner");
            }
            
            // Finalize auction
            auction.state = AuctionState::Finalized;
            
            // In a real contract, this would transfer funds and NFT
            
            Ok(())
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
    fn test_vulnerable_auction_logic() {
        let mut platform = vulnerable::AuctionPlatform::new();
        let auction_id = 1;
        let creator = [1u8; 32];
        let bidder = [2u8; 32];
        
        // Create auction
        platform.auctions.insert(auction_id, vulnerable::Auction {
            item_id: 1,
            creator,
            start_time: 100,
            end_time: 200,
            reserve_price: 100,
            highest_bid: 0,
            highest_bidder: None,
            state: vulnerable::AuctionState::Initialized,
        });
        
        // Start auction
        platform.current_time = 50; // Before start time
        let result = platform.start_auction(auction_id);
        assert!(result.is_ok()); // VULNERABILITY: Allows starting before start time
        
        // Place bid
        let result = platform.place_bid(auction_id, bidder, 150);
        assert!(result.is_ok());
        
        // Advance time past end
        platform.advance_time(200); // Now at 250, past end_time
        
        // VULNERABILITY: Can still place bid after end time
        let result = platform.place_bid(auction_id, [3u8; 32], 200);
        assert!(result.is_ok());
        
        // VULNERABILITY: Can finalize auction before end time
        platform.current_time = 50; // Reset time to before end
        let result = platform.finalize_auction(auction_id);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_vulnerable_staking_logic() {
        let mut platform = vulnerable::AuctionPlatform::new();
        let staker = [1u8; 32];
        
        // Create staking account
        platform.staking_accounts.insert(staker, vulnerable::StakingAccount {
            owner: staker,
            staked_amount: 1000,
            reward_balance: 0,
            last_claim_time: 0,
        });
        
        // Advance time 1 day
        platform.advance_time(86400);
        
        // Claim rewards
        let result = platform.claim_rewards(staker);
        assert!(result.is_ok());
        let rewards1 = result.unwrap();
        assert_eq!(rewards1, 100_000); // 1000 * 100 * 86400 / 86400 = 100,000
        
        // VULNERABILITY: Can claim again immediately with same result
        // because last_claim_time was never updated
        let result = platform.claim_rewards(staker);
        assert!(result.is_ok());
        let rewards2 = result.unwrap();
        assert_eq!(rewards2, 100_000); // Same amount again
    }
    
    #[test]
    fn test_secure_auction_logic() {
        let mut platform = secure::AuctionPlatform::new();
        let auction_id = 1;
        let creator = [1u8; 32];
        let bidder = [2u8; 32];
        
        // Create auction
        platform.auctions.insert(auction_id, secure::Auction {
            item_id: 1,
            creator,
            start_time: 100,
            end_time: 200,
            reserve_price: 100,
            highest_bid: 0,
            highest_bidder: None,
            state: secure::AuctionState::Initialized,
        });
        
        // Try to start auction before start time
        platform.current_time = 50;
        let result = platform.start_auction(auction_id);
        assert!(result.is_err()); // FIXED: Properly checks start time
        
        // Start auction at correct time
        platform.current_time = 100;
        let result = platform.start_auction(auction_id);
        assert!(result.is_ok());
        
        // Place bid
        let result = platform.place_bid(auction_id, bidder, 150);
        assert!(result.is_ok());
        
        // Advance time past end
        platform.advance_time(150); // Now at 250, past end_time
        
        // FIXED: Cannot place bid after end time
        let result = platform.place_bid(auction_id, [3u8; 32], 200);
        assert!(result.is_err());
        
        // Finalize auction (works now because we're past end time)
        let result = platform.finalize_auction(auction_id);
        assert!(result.is_ok());
        
        // Cannot finalize again
        let result = platform.finalize_auction(auction_id);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_secure_staking_logic() {
        let mut platform = secure::AuctionPlatform::new();
        let staker = [1u8; 32];
        
        // Set total staked
        platform.total_staked = 1000;
        
        // Create staking account
        platform.staking_accounts.insert(staker, secure::StakingAccount {
            owner: staker,
            staked_amount: 1000,
            reward_balance: 0,
            last_claim_time: 0,
            accumulated_rewards: 0,
        });
        
        // Advance time 1 day
        platform.advance_time(86400);
        
        // Claim rewards
        let result = platform.claim_rewards(staker);
        assert!(result.is_ok());
        let rewards1 = result.unwrap();
        assert_eq!(rewards1, 100_000);
        
        // FIXED: Cannot double claim
        let result = platform.claim_rewards(staker);
        assert!(result.is_ok());
        let rewards2 = result.unwrap();
        assert_eq!(rewards2, 0); // No new rewards since last claim
    }
}
