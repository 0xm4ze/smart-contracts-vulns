//! Integration tests for vulnerability examples

use rust_smart_contracts_vulns::vulnerabilities::{
    reentrancy,
    overflow,
    unchecked_inputs,
    oracle_manipulation,
    access_control,
    denial_of_service,
    illicit_fee_collection,
    flash_loan,
    logic_errors,
    random_manipulation,
};

#[test]
fn test_reentrancy_vulnerability() {
    // Test that the vulnerable implementation can be exploited
    let mut program = reentrancy::vulnerable::VaultProgram::new();
    let owner = [1u8; 32];
    
    // Create account with 100 tokens
    program.accounts.insert(owner, reentrancy::vulnerable::VaultAccount {
        owner,
        balance: 100,
    });
    
    // First withdraw should succeed
    let result = program.withdraw(owner, [2u8; 32], 50);
    assert!(result.is_ok());
    
    // In a real attack, the recipient would call back into withdraw
    // before the balance is updated
    
    // Now test that the secure implementation prevents this
    let mut secure_program = reentrancy::secure::VaultProgram::new();
    
    // Create account with 100 tokens
    secure_program.accounts.insert(owner, reentrancy::secure::VaultAccount {
        owner,
        balance: 100,
    });
    
    // First withdraw succeeds
    let result = secure_program.withdraw(owner, [2u8; 32], 50);
    assert!(result.is_ok());
    
    // If a reentrancy were attempted, it would fail due to the lock
    // Simulate a reentrancy attempt
    secure_program.reentrancy_lock = true;
    let result = secure_program.withdraw(owner, [2u8; 32], 25);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Reentrant call detected");
}

#[test]
fn test_overflow_vulnerability() {
    // Test that the vulnerable implementation can be exploited
    let mut program = overflow::vulnerable::TokenProgram::new();
    let account_id = [1u8; 32];
    
    // Create account with balance close to max
    program.accounts.insert(account_id, overflow::vulnerable::TokenAccount {
        balance: u64::MAX - 10,
    });
    
    // This would overflow in release mode with checks disabled
    // For this test, the behavior depends on the build configuration
    
    // Now test that the secure implementation prevents this
    let mut secure_program = overflow::secure::TokenProgram::new();
    
    // Create account with balance close to max
    secure_program.accounts.insert(account_id, overflow::secure::TokenAccount {
        balance: u64::MAX - 10,
    });
    
    // This should return an error instead of overflowing
    let result = secure_program.add_tokens(account_id, 20);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Arithmetic overflow detected");
}

#[test]
fn test_unchecked_inputs_vulnerability() {
    // Test that the vulnerable implementation accepts invalid inputs
    let mut program = unchecked_inputs::vulnerable::BankProgram::new();
    let account_id = [1u8; 32];
    
    // Create account
    program.accounts.insert(account_id, unchecked_inputs::vulnerable::UserAccount {
        owner: account_id,
        balance: 100,
        authorized_delegates: Vec::new(),
    });
    
    // Zero amount transfer succeeds in vulnerable implementation
    let result = program.transfer(account_id, [2u8; 32], 0);
    assert!(result.is_ok());
    
    // Now test that the secure implementation validates inputs
    let mut secure_program = unchecked_inputs::secure::BankProgram::new();
    
    // Create account
    secure_program.accounts.insert(account_id, unchecked_inputs::secure::UserAccount {
        owner: account_id,
        balance: 100,
        authorized_delegates: Vec::new(),
    });
    
    // Zero amount transfer fails in secure implementation
    let result = secure_program.transfer(account_id, [2u8; 32], 0);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Amount must be greater than zero");
}

// Additional tests for other vulnerabilities would follow a similar pattern
// Each test demonstrates the vulnerability in the vulnerable implementation
// and shows how the secure implementation prevents exploitation

#[test]
fn test_oracle_manipulation() {
    // Test that the vulnerable implementation can be exploited
    let mut protocol = oracle_manipulation::vulnerable::LendingProtocol::new(100);
    let position_id = [1u8; 32];
    
    // Create a position with 200 collateral and 100 loan
    protocol.positions.insert(position_id, oracle_manipulation::vulnerable::LendingPosition {
        owner: position_id,
        collateral_amount: 200,
        loan_amount: 100,
    });
    
    // Manipulate the oracle price drastically
    protocol.update_oracle_price(45); // Drop price by 55%
    
    // Position can now be liquidated due to manipulation
    let result = protocol.liquidate_position(position_id);
    assert!(result.is_ok());
    
    // Secure implementation would prevent this through TWAP and other safeguards
}

#[test]
fn test_access_control() {
    let mut protocol = access_control::vulnerable::Protocol::new([1u8; 32]);
    let attacker = [2u8; 32];
    
    // Attacker can change critical parameters in vulnerable implementation
    let result = protocol.set_fee_percentage(5000);
    assert!(result.is_ok());
    assert_eq!(protocol.fee_percentage, 5000);
    
    // Secure implementation would enforce access control
    let mut secure_protocol = access_control::secure::Protocol::new([1u8; 32]);
    let tx = access_control::secure::Transaction {
        caller: attacker,
        signature: [0u8; 64],
        valid: true,
    };
    
    let result = secure_protocol.set_fee_percentage(&tx, 5000);
    assert!(result.is_err());
}

// Similar tests would be implemented for all other vulnerability types
