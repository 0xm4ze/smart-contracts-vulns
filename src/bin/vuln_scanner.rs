use std::fs;
use std::path::{Path, PathBuf};
use std::error::Error;
use std::collections::HashMap;
use regex::Regex;
use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a Rust smart contract for potential vulnerabilities
    Scan {
        /// Path to the smart contract or project to scan
        #[arg(short, long)]
        path: String,
        
        /// Platform to target (solana, near, cosmwasm, substrate, or all)
        #[arg(short, long, default_value = "all")]
        platform: String,
        
        /// Generate a detailed report
        #[arg(short, long)]
        detailed: bool,
    },
    
    /// Generate a security checklist for a specific platform
    Checklist {
        /// Platform to generate checklist for (solana, near, cosmwasm, substrate, or all)
        #[arg(short, long, default_value = "all")]
        platform: String,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },
}

/// Vulnerability pattern to check for
struct VulnerabilityPattern {
    name: String,
    description: String,
    regex: Regex,
    severity: Severity,
    platform: Platform,
}

#[derive(PartialEq)]
enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "{}", "HIGH".red().bold()),
            Severity::Medium => write!(f, "{}", "MEDIUM".yellow().bold()),
            Severity::Low => write!(f, "{}", "LOW".green()),
            Severity::Info => write!(f, "{}", "INFO".blue()),
        }
    }
}

#[derive(PartialEq, Clone)]
enum Platform {
    Solana,
    Near,
    CosmWasm,
    Substrate,
    All,
}

impl Platform {
    fn from_string(s: &str) -> Platform {
        match s.to_lowercase().as_str() {
            "solana" => Platform::Solana,
            "near" => Platform::Near,
            "cosmwasm" => Platform::CosmWasm,
            "substrate" => Platform::Substrate,
            _ => Platform::All,
        }
    }
}

/// Vulnerability finding
struct Finding {
    vulnerability: String,
    file: PathBuf,
    line: usize,
    code: String,
    description: String,
    severity: Severity,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path, platform, detailed } => {
            println!("Scanning {} for vulnerabilities...", path);
            let platform_enum = Platform::from_string(platform);
            
            let findings = scan_for_vulnerabilities(path, &platform_enum)?;
            
            print_findings(&findings, *detailed);
            
            println!("\nScan complete! Found {} potential vulnerabilities.", findings.len());
        },
        Commands::Checklist { platform, output } => {
            println!("Generating security checklist for {}...", platform);
            generate_checklist(platform, output.as_deref())?;
        },
    }

    Ok(())
}

/// Create vulnerability patterns to scan for
fn create_vulnerability_patterns() -> Vec<VulnerabilityPattern> {
    let mut patterns = Vec::new();
    
    // Reentrancy patterns
    patterns.push(VulnerabilityPattern {
        name: "Reentrancy Vulnerability".to_string(),
        description: "Potential reentrancy vulnerability detected. Consider implementing a reentrancy guard or following the checks-effects-interactions pattern.".to_string(),
        regex: Regex::new(r"invoke(_signed)?\(.*\).*;\s*.*\w+\s*[-+*\/]?=").unwrap(),
        severity: Severity::High,
        platform: Platform::Solana,
    });
    
    // Integer overflow patterns
    patterns.push(VulnerabilityPattern {
        name: "Integer Overflow".to_string(),
        description: "Potential integer overflow. Consider using checked, saturating, or wrapping operations.".to_string(),
        regex: Regex::new(r"\w+\s*[+\-*\/]=\s*\w+|let\s+\w+\s*=\s*\w+\s*[+\-*\/]\s*\w+").unwrap(),
        severity: Severity::Medium,
        platform: Platform::All,
    });
    
    // Unchecked account ownership
    patterns.push(VulnerabilityPattern {
        name: "Missing Ownership Check".to_string(),
        description: "Account ownership is not verified. Always check account.owner before using account data.".to_string(),
        regex: Regex::new(r"let\s+\w+\s*=\s*next_account_info\(.*\).*;\s*(?!.*owner)").unwrap(),
        severity: Severity::High,
        platform: Platform::Solana,
    });
    
    // Missing access control
    patterns.push(VulnerabilityPattern {
        name: "Missing Access Control".to_string(),
        description: "Potential missing access control. Verify that only authorized users can call this function.".to_string(),
        regex: Regex::new(r"pub\s+fn\s+\w+\(.*\).*\{(?!.*require\(|.*assert\(|.*if\s+.*==)").unwrap(),
        severity: Severity::High,
        platform: Platform::All,
    });
    
    // Unchecked return values
    patterns.push(VulnerabilityPattern {
        name: "Unchecked Return Value".to_string(),
        description: "Return value from external call is not checked. Always check the result of external calls.".to_string(),
        regex: Regex::new(r"invoke(_signed)?\(.*\);(?!\s*\?)").unwrap(),
        severity: Severity::Medium,
        platform: Platform::Solana,
    });
    
    // Add more patterns here...
    
    patterns
}

/// Scan a directory for vulnerabilities
fn scan_for_vulnerabilities(path: &str, platform: &Platform) -> Result<Vec<Finding>, Box<dyn Error>> {
    let patterns = create_vulnerability_patterns();
    let mut findings = Vec::new();
    
    let path = Path::new(path);
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            
            if entry_path.is_dir() {
                // Skip target directory and hidden directories
                if entry_path.file_name().unwrap_or_default().to_string_lossy().starts_with('.') ||
                   entry_path.file_name().unwrap_or_default() == "target" {
                    continue;
                }
                
                let mut sub_findings = scan_for_vulnerabilities(
                    entry_path.to_string_lossy().as_ref(), 
                    platform
                )?;
                findings.append(&mut sub_findings);
            } else if let Some(ext) = entry_path.extension() {
                if ext == "rs" {
                    let mut file_findings = scan_file(&entry_path, &patterns, platform)?;
                    findings.append(&mut file_findings);
                }
            }
        }
    } else if path.is_file() && path.extension().map_or(false, |ext| ext == "rs") {
        let mut file_findings = scan_file(path, &patterns, platform)?;
        findings.append(&mut file_findings);
    } else {
        println!("Path is not a Rust file or directory: {}", path.display());
    }
    
    Ok(findings)
}

/// Scan a single file for vulnerabilities
fn scan_file(
    file_path: &Path, 
    patterns: &[VulnerabilityPattern],
    target_platform: &Platform
) -> Result<Vec<Finding>, Box<dyn Error>> {
    let mut findings = Vec::new();
    
    let content = fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();
    
    for (line_idx, line) in lines.iter().enumerate() {
        for pattern in patterns {
            // Skip if this pattern is for a different platform
            if &pattern.platform != target_platform && pattern.platform != Platform::All && *target_platform != Platform::All {
                continue;
            }
            
            if pattern.regex.is_match(line) {
                let context_start = line_idx.saturating_sub(2);
                let context_end = std::cmp::min(line_idx + 3, lines.len());
                let code_context = lines[context_start..context_end].join("\n");
                
                findings.push(Finding {
                    vulnerability: pattern.name.clone(),
                    file: file_path.to_path_buf(),
                    line: line_idx + 1,
                    code: code_context,
                    description: pattern.description.clone(),
                    severity: pattern.severity,
                });
            }
        }
    }
    
    Ok(findings)
}

/// Print findings to the console
fn print_findings(findings: &[Finding], detailed: bool) {
    if findings.is_empty() {
        println!("No vulnerabilities found!");
        return;
    }
    
    // Group findings by severity
    let mut by_severity: HashMap<Severity, Vec<&Finding>> = HashMap::new();
    for finding in findings {
        by_severity.entry(finding.severity).or_insert_with(Vec::new).push(finding);
    }
    
    // Print summary
    println!("\n{}", "Summary:".bold());
    println!("{} potential vulnerabilities found:", findings.len());
    
    let severities = [Severity::High, Severity::Medium, Severity::Low, Severity::Info];
    for severity in &severities {
        let count = by_severity.get(severity).map_or(0, |v| v.len());
        if count > 0 {
            println!("  {} : {}", severity, count);
        }
    }
    
    // Print detailed findings
    println!("\n{}", "Findings:".bold());
    
    for severity in &severities {
        if let Some(sev_findings) = by_severity.get(severity) {
            for (i, finding) in sev_findings.iter().enumerate() {
                println!("\n[{}] {} ({})", i + 1, finding.vulnerability.bold(), finding.severity);
                println!("File: {}", finding.file.display().to_string().cyan());
                println!("Line: {}", finding.line.to_string().cyan());
                println!("Description: {}", finding.description);
                
                if detailed {
                    println!("\nCode:");
                    println!("{}", finding.code);
                }
            }
        }
    }
}

/// Generate a security checklist
fn generate_checklist(platform: &str, output_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    let checklist_content = match platform.to_lowercase().as_str() {
        "solana" => {
            let content = "# Solana-Specific Security Checklist\n\nThis is a placeholder for the Solana security checklist.\nPlease refer to the full checklist in the checklists directory.";
            content
        },
        _ => {
            let content = "# General Rust Smart Contract Security Checklist\n\nThis is a placeholder for the general security checklist.\nPlease refer to the full checklist in the checklists directory.";
            content
        }
    };
    
    if let Some(path) = output_path {
        fs::write(path, checklist_content)?;
        println!("Checklist written to {}", path);
    } else {
        println!("\n{}", checklist_content);
    }
    
    Ok(())
}
