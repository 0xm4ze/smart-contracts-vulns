# Contributing to Rust Smart Contract Vulnerabilities

Thank you for your interest in contributing to this educational repository on Rust smart contract vulnerabilities! This document provides guidelines and instructions for contributing.

## Code of Conduct

All contributors are expected to adhere to professional standards of conduct. Please be respectful and constructive in all interactions.

## Ways to Contribute

You can contribute to this project in several ways:

1. **Adding new vulnerability examples**: Implement new vulnerability types not currently covered
2. **Improving existing examples**: Enhance existing examples with better code, explanations, or tests
3. **Adding platform-specific examples**: Provide specific examples for platforms like Solana, NEAR, or others
4. **Documentation improvements**: Enhance explanations, add more detection methods, or provide real-world examples
5. **Bug fixes**: Fix any issues in the existing code examples
6. **Test cases**: Add more comprehensive test cases demonstrating exploitation and prevention

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/0xm4ze/rust-smart-contracts-vulns.git`
3. Create a new branch for your changes: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run the tests: `cargo test`
6. Commit your changes
7. Push to your branch
8. Create a pull request

## Contribution Guidelines

### Adding a New Vulnerability

1. Create a new file in `src/vulnerabilities/` named after the vulnerability
2. Implement the `Vulnerability` trait
3. Provide both vulnerable and secure code examples
4. Add comprehensive tests
5. Update `src/vulnerabilities/mod.rs` to include your new module
6. Update `src/lib.rs` to re-export your vulnerability type
7. Update the README.md to include information about the new vulnerability

### Code Style

- Follow Rust's official style guidelines
- Use meaningful variable and function names
- Include comprehensive documentation comments
- Write clear, concise code that demonstrates the vulnerability without unnecessary complexity

### Documentation

- All public items should have documentation comments
- Use Rust's standard documentation format
- Provide clear explanations of vulnerabilities and remediation strategies
- Include references to external resources where applicable

### Tests

- Each vulnerability should have tests demonstrating both the vulnerable and secure implementations
- Tests should clearly show how the vulnerability can be exploited
- Tests should also demonstrate how the secure implementation prevents exploitation

## Pull Request Process

1. Ensure your code passes all tests
2. Update documentation to reflect changes if necessary
3. Your PR should clearly describe what it adds or changes
4. PRs will be reviewed by maintainers
5. Address any feedback from code reviews
6. Once approved, your PR will be merged

## License

By contributing to this repository, you agree that your contributions will be licensed under the project's MIT license.

## Questions?

If you have any questions about contributing, feel free to open an issue asking for clarification.

Thank you for helping make this resource better for the Rust smart contract security community!
