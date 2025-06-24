# Rust Smart Contract Vulnerabilities

A comprehensive guide to common vulnerabilities in Rust-based smart contracts, designed specifically for auditors and security researchers.

## Overview

This repository provides examples, explanations, and detection techniques for various vulnerabilities commonly found in Rust-based smart contracts, particularly those deployed on platforms such as Solana, NEAR, and other blockchains supporting Rust-based contracts.

Each vulnerability is explained with:
- Detailed description and impact
- Vulnerable code examples
- Secure code alternatives
- Detection methodologies
- Real-world examples (where applicable)

## Vulnerabilities Covered

1. **Reentrancy**
   - Cross-program invocation vulnerabilities
   - How they differ from Ethereum's reentrancy issues

2. **Integer Overflow/Underflow**
   - Arithmetic operation safety
   - Rust's handling vs. explicit checks

3. **Unchecked Inputs**
   - Missing validation
   - Deserialization vulnerabilities

4. **Oracle Manipulation**
   - Price oracle vulnerabilities
   - Data feed tampering

5. **Access Control**
   - Privilege escalation
   - Missing authorization checks

6. **Denial of Service**
   - Resource exhaustion
   - Logic-based DoS

7. **Illicit Fee Collection**
   - Fee redirection
   - Hidden fee structures

8. **Flash Loan Attacks**
   - Temporary asset control exploitation
   - Market manipulation

9. **Logic Errors**
   - Incorrect state transitions
   - Business logic flaws

10. **Random Number Manipulation**
    - Predictable randomness
    - Seed manipulation

11. **Signature Verification Bypass**
    - Improper signature validation
    - Replay attack vulnerabilities

12. **Account Confusion**
    - Incorrect account validation
    - Cross-instance attacks on Solana

13. **Front-Running**
    - Transaction ordering exploitation
    - MEV vulnerabilities in Rust contexts

14. **Inadequate Event Emissions**
    - Missing critical events for off-chain monitoring
    - Insufficient logging for security audit trails

15. **Storage/Account Management**
    - Memory safety issues specific to blockchain contexts
    - Account data validation failures

## Usage

The repository is structured to allow easy navigation between vulnerability types. Each vulnerability has:

- Explanatory documentation in markdown
- Code examples showing both vulnerable and secure implementations
- Test cases demonstrating exploitation and mitigation

## Platform-Specific Vulnerabilities

### Solana

- Account validation issues
- Cross-Program Invocation (CPI) security concerns
- PDAs and bump seeds validation
- Instruction data validation
- Compute budget considerations

### NEAR

- Cross-contract call vulnerabilities
- Storage management issues
- Gas efficiency concerns
- Promise chain vulnerabilities

### CosmWasm (Rust on Cosmos)

- Message passing vulnerabilities
- State management issues
- Contract migration risks

### Substrate/Polkadot

- Runtime module interactions
- Governance mechanism vulnerabilities
- Parachain-specific concerns

## Interactive Tools

This repository includes several tools to enhance the learning experience:

1. **Vulnerability Scanner CLI**: A command-line tool that can scan Rust smart contract code for potential security issues.
2. **Exploitation Sandbox**: Interactive examples where you can safely experiment with exploiting vulnerabilities.
3. **Security Checklist Generator**: Creates a tailored security checklist based on your project's characteristics.

## Security Checklists

We provide comprehensive security checklists for auditors reviewing Rust smart contracts:

- **General Rust Smart Contract Checklist**: Universal security considerations for all Rust-based smart contracts
- **Solana-Specific Checklist**: Focusing on Account validation, PDAs, and CPIs
- **NEAR-Specific Checklist**: Addressing cross-contract calls and storage concerns
- **Audit Preparation Checklist**: How to prepare a Rust smart contract codebase for a security audit

## Real-World Case Studies

Learn from historical vulnerabilities discovered in production systems:

- **Case Study 1**: Cross-program invocation vulnerability in a Solana protocol
- **Case Study 2**: Integer overflow exploit in a NEAR application
- **Case Study 3**: Access control bypass in a CosmWasm contract
- **Case Study 4**: Logic error in a high-value DeFi application

## For Auditors

This repository serves as both a reference and a training tool for auditors specializing in Rust-based smart contracts. We recommend:

1. Start by understanding the fundamental differences between Rust smart contracts and those written in other languages like Solidity
2. Review each vulnerability type and understand its specific manifestation in Rust
3. Use the test cases to practice identifying these vulnerabilities
4. Contribute your findings and improvements

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

The code examples in this repository demonstrate vulnerabilities for educational purposes. They should not be used in production environments.
