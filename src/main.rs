use rust_smart_contracts_vulns::vulnerabilities::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    println!("Rust Smart Contract Vulnerabilities Guide");
    println!("========================================");
    
    if args.len() > 1 {
        match args[1].to_lowercase().as_str() {
            "reentrancy" => print_vulnerability(&reentrancy::ReentrancyVulnerability),
            "overflow" => print_vulnerability(&overflow::OverflowVulnerability),
            "unchecked" => print_vulnerability(&unchecked_inputs::UncheckedInputsVulnerability),
            "oracle" => print_vulnerability(&oracle_manipulation::OracleManipulationVulnerability),
            "access" => print_vulnerability(&access_control::AccessControlVulnerability),
            "dos" => print_vulnerability(&denial_of_service::DoSVulnerability),
            "fee" => print_vulnerability(&illicit_fee_collection::IllicitFeeVulnerability),
            "flash" => print_vulnerability(&flash_loan::FlashLoanVulnerability),
            "logic" => print_vulnerability(&logic_errors::LogicErrorVulnerability),
            "random" => print_vulnerability(&random_manipulation::RandomManipulationVulnerability),
            "list" => list_vulnerabilities(),
            _ => {
                println!("Unknown vulnerability type: {}", args[1]);
                println!("Use 'list' to see all available vulnerabilities");
            }
        }
    } else {
        print_usage();
    }
}

fn print_usage() {
    println!("Usage: rust-smart-contracts-vulns [vulnerability-type]");
    println!("Example: rust-smart-contracts-vulns reentrancy");
    println!("Use 'list' to see all available vulnerabilities");
}

fn list_vulnerabilities() {
    println!("Available vulnerability types:");
    println!("  - reentrancy: Reentrancy attacks");
    println!("  - overflow: Integer overflow/underflow");
    println!("  - unchecked: Unchecked inputs");
    println!("  - oracle: Oracle manipulation");
    println!("  - access: Access control issues");
    println!("  - dos: Denial of service");
    println!("  - fee: Illicit fee collection");
    println!("  - flash: Flash loan attacks");
    println!("  - logic: Logic errors");
    println!("  - random: Random number manipulation");
}

fn print_vulnerability(vuln: &dyn Vulnerability) {
    println!("\n{}", vuln.name());
    println!("{}", "=".repeat(vuln.name().len()));
    
    println!("\nDescription:");
    println!("{}", vuln.description());
    
    println!("\nAffected Platforms:");
    for platform in vuln.affected_platforms() {
        println!("  - {}", platform);
    }
    
    println!("\nExample Vulnerability:");
    println!("{}", vuln.exploit_example());
    
    println!("\nDetection Methods:");
    for method in vuln.detection_methods() {
        println!("  - {}", method);
    }
    
    println!("\nRemediation Strategies:");
    for strategy in vuln.remediation() {
        println!("  - {}", strategy);
    }
}
