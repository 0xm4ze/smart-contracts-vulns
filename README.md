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

## Usage

The repository is structured to allow easy navigation between vulnerability types. Each vulnerability has:
- Explanatory documentation in markdown
- Code examples showing both vulnerable and secure implementations
- Test cases demonstrating exploitation and mitigation

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
