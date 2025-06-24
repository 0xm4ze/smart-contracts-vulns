//! Module containing examples of different vulnerability types in Rust smart contracts
//! 
//! Each submodule focuses on a specific vulnerability class, providing:
//! - Explanation of the vulnerability
//! - Code examples of vulnerable implementations
//! - Secure alternatives and best practices
//! - Detection methodologies for auditors

pub mod reentrancy;
pub mod overflow;
pub mod unchecked_inputs;
pub mod oracle_manipulation;
pub mod access_control;
pub mod denial_of_service;
pub mod illicit_fee_collection;
pub mod flash_loan;
pub mod logic_errors;
pub mod random_manipulation;
pub mod signature_verification;
pub mod account_confusion;
pub mod front_running;
pub mod inadequate_events;
pub mod storage_management;

/// Common trait for all vulnerability examples
pub trait Vulnerability {
    /// Name of the vulnerability
    fn name(&self) -> &'static str;
    
    /// Description of the vulnerability
    fn description(&self) -> &'static str;
    
    /// Platforms where this vulnerability is commonly found
    fn affected_platforms(&self) -> Vec<&'static str>;
    
    /// Example of exploiting the vulnerability
    fn exploit_example(&self) -> &'static str;
    
    /// Detection methods for auditors
    fn detection_methods(&self) -> Vec<&'static str>;
    
    /// Remediation strategies
    fn remediation(&self) -> Vec<&'static str>;
}
