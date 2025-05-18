//! # Denial of Service Vulnerability
//!
//! Denial of Service (DoS) vulnerabilities occur when a smart contract can be
//! manipulated to prevent legitimate users from accessing its functionality,
//! either temporarily or permanently. This can happen through resource exhaustion,
//! logic locks, or other means of disrupting normal contract operations.
//!
//! In Rust smart contracts, DoS can manifest in various ways, from loops with
//! unbounded iterations to storage exhaustion attacks.

use crate::vulnerabilities::Vulnerability;

/// Represents a denial of service vulnerability example
pub struct DoSVulnerability;

impl Vulnerability for DoSVulnerability {
    fn name(&self) -> &'static str {
        "Denial of Service Vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Occurs when a smart contract can be manipulated to prevent legitimate users \
        from accessing its functionality, either temporarily or permanently. This can \
        happen through resource exhaustion, logic locks, or other means of disrupting \
        normal contract operations."
    }
    
    fn affected_platforms(&self) -> Vec<&'static str> {
        vec!["Solana", "NEAR", "Polkadot", "All Rust-based contracts"]
    }
    
    fn exploit_example(&self) -> &'static str {
        r#"
        // Vulnerable function with unbounded iteration
        pub fn process_all_accounts(ctx: Context<ProcessAccounts>) -> Result<()> {
            // VULNERABILITY: Unbounded iteration can lead to compute budget exhaustion
            // A malicious user could create many small accounts to force this function
            // to hit computational limits and fail
            
            for account in ctx.accounts.user_accounts.iter() {
                process_account(account)?;
            }
            
            Ok(())
        }
        
        // Vulnerable function with potential blocking
        pub fn withdraw_all(ctx: Context<WithdrawAll>) -> Result<()> {
            // VULNERABILITY: This function requires all users to be processed
            // If one user's processing fails, all users are blocked
            
            let mut total_processed = 0;
            
            for user in ctx.accounts.users.iter() {
                // If this fails for any user, the entire transaction fails
                process_withdrawal(user)?;
                total_processed += 1;
            }
            
            // Update global state
            ctx.accounts.global_state.last_processed_count = total_processed;
            
            Ok(())
        }
        "#
    }
    
    fn detection_methods(&self) -> Vec<&'static str> {
        vec![
            "Look for loops that iterate over user-controlled collections",
            "Check for functions that process multiple accounts in a single transaction",
            "Identify critical contract operations that could be blocked by a failed transaction",
            "Examine storage patterns that could allow unbounded growth",
            "Look for array operations without proper bounds checking",
        ]
    }
    
    fn remediation(&self) -> Vec<&'static str> {
        vec![
            "Implement paging for operations that iterate over large collections",
            "Add limits to the number of items processed in a single transaction",
            "Use a pull-payment pattern instead of pushing to many recipients",
            "Design fault-tolerant systems that can handle individual failures",
            "Add storage limits and garbage collection mechanisms",
        ]
    }
}

/// Example of vulnerable code susceptible to DoS
pub mod vulnerable {
    pub struct Auction {
        pub highest_bidder: Option<[u8; 32]>,
        pub highest_bid: u64,
        pub bidders: Vec<[u8; 32]>,
        pub bids: Vec<(u64, [u8; 32])>,
        pub ended: bool,
    }
    
    impl Auction {
        pub fn new() -> Self {
            Self {
                highest_bidder: None,
                highest_bid: 0,
                bidders: Vec::new(),
                bids: Vec::new(),
                ended: false,
            }
        }
        
        /// Vulnerable function with unbounded storage growth
        pub fn place_bid(&mut self, bidder: [u8; 32], amount: u64) -> Result<(), &'static str> {
            if self.ended {
                return Err("Auction already ended");
            }
            
            if amount <= self.highest_bid {
                return Err("Bid too low");
            }
            
            // Update highest bid
            self.highest_bidder = Some(bidder);
            self.highest_bid = amount;
            
            // VULNERABILITY: Unbounded array growth
            // Every bid is stored, regardless of how many there are
            // This could lead to storage exhaustion
            self.bids.push((amount, bidder));
            
            // VULNERABILITY: Duplicate tracking can lead to array explosion
            // No check if bidder already exists in the array
            self.bidders.push(bidder);
            
            Ok(())
        }
        
        /// Vulnerable function with inefficient mass refund
        pub fn end_auction(&mut self) -> Result<(), &'static str> {
            if self.ended {
                return Err("Auction already ended");
            }
            
            self.ended = true;
            
            // VULNERABILITY: All refunds must succeed or the auction cannot end
            // If any refund fails, the entire transaction reverts
            
            // VULNERABILITY: Unbounded iteration
            // If there are too many bidders, this could exceed computational limits
            for bidder in &self.bidders {
                if Some(*bidder) != self.highest_bidder {
                    self.refund_bidder(*bidder)?;
                }
            }
            
            Ok(())
        }
        
        /// Helper function for refunds
        fn refund_bidder(&self, bidder: [u8; 32]) -> Result<(), &'static str> {
            // In a real contract, this would transfer funds
            // If the transfer failed (e.g., due to a malicious recipient),
            // it would cause the entire end_auction function to fail
            
            // Simulate a potential refund failure for a specific bidder
            if bidder == [0xaa; 32] {
                return Err("Refund failed");
            }
            
            Ok(())
        }
    }
}

/// Example of secure code that prevents DoS
pub mod secure {
    pub struct Auction {
        pub highest_bidder: Option<[u8; 32]>,
        pub highest_bid: u64,
        pub bidder_amounts: std::collections::HashMap<[u8; 32], u64>,
        pub ended: bool,
        pub max_bidders: usize,
    }
    
    impl Auction {
        pub fn new(max_bidders: usize) -> Self {
            Self {
                highest_bidder: None,
                highest_bid: 0,
                bidder_amounts: std::collections::HashMap::new(),
                ended: false,
                max_bidders,
            }
        }
        
        /// Secure function with bounded storage
        pub fn place_bid(&mut self, bidder: [u8; 32], amount: u64) -> Result<(), &'static str> {
            if self.ended {
                return Err("Auction already ended");
            }
            
            if amount <= self.highest_bid {
                return Err("Bid too low");
            }
            
            // FIXED: Limit the total number of bidders
            if !self.bidder_amounts.contains_key(&bidder) && self.bidder_amounts.len() >= self.max_bidders {
                return Err("Maximum number of bidders reached");
            }
            
            // Update highest bid
            self.highest_bidder = Some(bidder);
            self.highest_bid = amount;
            
            // FIXED: Efficiently track bids with a HashMap
            // Only stores one entry per bidder, preventing storage explosion
            self.bidder_amounts.insert(bidder, amount);
            
            Ok(())
        }
        
        /// Secure function with pull pattern instead of push
        pub fn end_auction(&mut self) -> Result<(), &'static str> {
            if self.ended {
                return Err("Auction already ended");
            }
            
            self.ended = true;
            
            // FIXED: No refunds are processed here
            // Instead, bidders will call claim_refund themselves (pull pattern)
            
            Ok(())
        }
        
        /// Allows bidders to claim their refunds individually
        pub fn claim_refund(&mut self, bidder: [u8; 32]) -> Result<(), &'static str> {
            if !self.ended {
                return Err("Auction not ended yet");
            }
            
            // Check if this is the highest bidder (not eligible for refund)
            if Some(bidder) == self.highest_bidder {
                return Err("Highest bidder cannot claim refund");
            }
            
            // Check if bidder has a refund to claim
            let amount = match self.bidder_amounts.get(&bidder) {
                Some(amount) => *amount,
                None => return Err("No bid found for this bidder"),
            };
            
            // Process refund
            // In a real contract, this would transfer funds
            
            // Remove the record after successful refund
            self.bidder_amounts.remove(&bidder);
            
            Ok(())
        }
        
        /// Function to process refunds in batches with limits
        pub fn process_refund_batch(&mut self, max_refunds: usize) -> Result<usize, &'static str> {
            if !self.ended {
                return Err("Auction not ended yet");
            }
            
            // FIXED: Process refunds in bounded batches
            let mut refunded_count = 0;
            let highest_bidder_key = self.highest_bidder.unwrap_or([0; 32]);
            
            // Get bidders to refund (excluding highest bidder)
            let bidders_to_refund: Vec<[u8; 32]> = self.bidder_amounts.keys()
                .filter(|&&k| k != highest_bidder_key)
                .cloned()
                .take(max_refunds)
                .collect();
            
            // Process refunds for this batch
            for bidder in bidders_to_refund {
                // In a real contract, this would transfer funds
                // If a transfer fails, we continue with the next one
                let _ = self.process_single_refund(bidder);
                
                // Remove the record
                self.bidder_amounts.remove(&bidder);
                refunded_count += 1;
            }
            
            Ok(refunded_count)
        }
        
        /// Helper function that doesn't revert the entire batch on failure
        fn process_single_refund(&self, bidder: [u8; 32]) -> Result<(), &'static str> {
            // In a real contract, this would transfer funds
            // We'd catch errors but not propagate them to the caller
            
            // Simulate a potential refund failure
            if bidder == [0xaa; 32] {
                // Just log the error but don't revert
                return Err("Refund failed for specific bidder");
            }
            
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_dos_attack() {
        let mut auction = vulnerable::Auction::new();
        
        // Place bids from multiple bidders
        for i in 1..100 {
            let bidder = [i as u8; 32];
            let amount = (i * 10) as u64;
            let _ = auction.place_bid(bidder, amount);
        }
        
        // Include the malicious bidder that will cause refunds to fail
        let malicious_bidder = [0xaa; 32];
        let _ = auction.place_bid(malicious_bidder, 2000);
        
        // The auction cannot end due to the malicious bidder
        let result = auction.end_auction();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Refund failed");
        
        // The auction is stuck in an open state
        assert_eq!(auction.ended, false);
    }
    
    #[test]
    fn test_secure_dos_prevention() {
        let mut auction = secure::Auction::new(100);
        
        // Place bids from multiple bidders
        for i in 1..50 {
            let bidder = [i as u8; 32];
            let amount = (i * 10) as u64;
            let _ = auction.place_bid(bidder, amount);
        }
        
        // Include the malicious bidder
        let malicious_bidder = [0xaa; 32];
        let _ = auction.place_bid(malicious_bidder, 2000);
        
        // The auction can end regardless of refund issues
        let result = auction.end_auction();
        assert!(result.is_ok());
        assert_eq!(auction.ended, true);
        
        // Process refunds in batches
        let refund_result = auction.process_refund_batch(10);
        assert!(refund_result.is_ok());
        
        // Even with a malicious bidder, other refunds can still be processed
        let _ = auction.claim_refund([5; 32]);
    }
}
