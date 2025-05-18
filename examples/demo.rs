//! A simple demo program to showcase the use of this library

use rust_smart_contracts_vulns::{
    vulnerabilities::{
        reentrancy::ReentrancyVulnerability,
        overflow::OverflowVulnerability,
        unchecked_inputs::UncheckedInputsVulnerability,
        oracle_manipulation::OracleManipulationVulnerability,
        access_control::AccessControlVulnerability,
        denial_of_service::DoSVulnerability,
        illicit_fee_collection::IllicitFeeVulnerability,
        flash_loan::FlashLoanVulnerability,
        logic_errors::LogicErrorVulnerability,
        random_manipulation::RandomManipulationVulnerability,
        Vulnerability,
    },
    VERSION,
};

fn main() {
    println!("Rust Smart Contract Vulnerabilities Demo - v{}", VERSION);
    println!("================================================\n");
    
    // List all vulnerability types
    let vulnerabilities: Vec<Box<dyn Vulnerability>> = vec![
        Box::new(ReentrancyVulnerability {}),
        Box::new(OverflowVulnerability {}),
        Box::new(UncheckedInputsVulnerability {}),
        Box::new(OracleManipulationVulnerability {}),
        Box::new(AccessControlVulnerability {}),
        Box::new(DoSVulnerability {}),
        Box::new(IllicitFeeVulnerability {}),
        Box::new(FlashLoanVulnerability {}),
        Box::new(LogicErrorVulnerability {}),
        Box::new(RandomManipulationVulnerability {}),
    ];
    
    // Print a summary of each vulnerability
    for (i, vuln) in vulnerabilities.iter().enumerate() {
        println!("{}. {}", i+1, vuln.name());
        println!("   Description: {}", vuln.description());
        println!("   Affected platforms: {}", vuln.affected_platforms().join(", "));
        println!();
    }
    
    // Provide more detailed information about a specific vulnerability
    // For demonstration, we'll use the reentrancy vulnerability
    detailed_report(&vulnerabilities[0]);
}

fn detailed_report(vulnerability: &Box<dyn Vulnerability>) {
    println!("Detailed Report: {}", vulnerability.name());
    println!("=".repeat(vulnerability.name().len() + 16));
    
    println!("\nDESCRIPTION:");
    println!("{}", vulnerability.description());
    
    println!("\nAFFECTED PLATFORMS:");
    for platform in vulnerability.affected_platforms() {
        println!("- {}", platform);
    }
    
    println!("\nVULNERABLE CODE EXAMPLE:");
    println!("{}", vulnerability.exploit_example());
    
    println!("\nDETECTION METHODS:");
    for (i, method) in vulnerability.detection_methods().iter().enumerate() {
        println!("{}. {}", i+1, method);
    }
    
    println!("\nREMEDIATION STRATEGIES:");
    for (i, strategy) in vulnerability.remediation().iter().enumerate() {
        println!("{}. {}", i+1, strategy);
    }
}
