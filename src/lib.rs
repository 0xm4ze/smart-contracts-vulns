// Main library file for rust-smart-contracts-vulns

//! # Rust Smart Contract Vulnerabilities
//! 
//! This library provides examples and explanations of common vulnerabilities
//! found in Rust-based smart contracts across various blockchain platforms.
//!
//! The code examples are intended for educational purposes to help auditors
//! identify and understand these vulnerabilities.

pub mod vulnerabilities;
pub mod utils;

/// Version of the library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Re-export common vulnerability types
pub use vulnerabilities::reentrancy::ReentrancyVulnerability;
pub use vulnerabilities::overflow::OverflowVulnerability;
pub use vulnerabilities::unchecked_inputs::UncheckedInputsVulnerability;
pub use vulnerabilities::oracle_manipulation::OracleManipulationVulnerability;
pub use vulnerabilities::access_control::AccessControlVulnerability;
pub use vulnerabilities::denial_of_service::DoSVulnerability;
pub use vulnerabilities::illicit_fee_collection::IllicitFeeVulnerability;
pub use vulnerabilities::flash_loan::FlashLoanVulnerability;
pub use vulnerabilities::logic_errors::LogicErrorVulnerability;
pub use vulnerabilities::random_manipulation::RandomManipulationVulnerability;

/// Helpful type aliases
pub type Result<T> = std::result::Result<T, Error>;

/// Custom error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Reentrancy attack detected")]
    Reentrancy,
    
    #[error("Integer overflow detected")]
    Overflow,
    
    #[error("Invalid input detected")]
    InvalidInput,
    
    #[error("Oracle manipulation detected")]
    OracleManipulation,
    
    #[error("Access control violation")]
    AccessControl,
    
    #[error("Denial of service condition")]
    DoS,
    
    #[error("Illicit fee detected")]
    IllicitFee,
    
    #[error("Flash loan attack detected")]
    FlashLoan,
    
    #[error("Logic error detected")]
    LogicError,
    
    #[error("Random manipulation detected")]
    RandomManipulation,
    
    #[error("Generic error: {0}")]
    Generic(String),
}
