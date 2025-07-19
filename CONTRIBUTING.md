# Contributing to Decentralized Identity Management System

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites
- Rust 1.70+
- IPFS node
- Git
- Basic understanding of blockchain and cryptography concepts

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/your-username/decentralized-identity-system.git
cd decentralized-identity-system

# Install dependencies and build
cargo build

# Run tests
cargo test

# Start IPFS daemon
ipfs daemon &
```

## 📋 How to Contribute

### 1. Reporting Bugs
- Use the GitHub issue tracker
- Include detailed reproduction steps
- Provide system information (OS, Rust version, etc.)
- Include relevant logs and error messages

### 2. Suggesting Features
- Open an issue with the "enhancement" label
- Describe the use case and expected behavior
- Consider implementation complexity and project scope

### 3. Code Contributions

#### Pull Request Process
1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes with proper tests
4. **Test** thoroughly: `cargo test`
5. **Commit** with descriptive messages
6. **Push** to your fork: `git push origin feature/amazing-feature`
7. **Open** a Pull Request

#### Code Standards
- Follow Rust naming conventions
- Use `cargo fmt` for formatting
- Run `cargo clippy` for linting
- Maintain test coverage above 80%
- Document public APIs with rustdoc

#### Commit Message Format
```
type(scope): brief description

Detailed explanation of changes if needed.

Fixes #issue-number
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## 🧪 Testing Guidelines

### Unit Tests
- Test all public functions
- Use property-based testing for cryptographic functions
- Mock external dependencies

### Integration Tests
- Test complete workflows
- Verify cross-component interactions
- Include performance benchmarks

### Example Test Structure
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_creation() {
        // Arrange
        let method = "example";
        
        // Act
        let (did_doc, _) = create_basic_did_document(method, KeyType::Ed25519).unwrap();
        
        // Assert
        assert!(did_doc.id.starts_with("did:example:"));
        assert!(did_doc.validate().is_ok());
    }
}
```

## 📚 Documentation

### Code Documentation
- Document all public APIs
- Include examples in rustdoc
- Explain complex algorithms
- Document security considerations

### Architecture Documentation
- Update PROJECT_STRUCTURE.md for architectural changes
- Add sequence diagrams for new workflows
- Document design decisions

## 🔒 Security Guidelines

### Security Review Process
- All cryptographic changes require security review
- Use established cryptographic libraries
- Avoid custom crypto implementations
- Consider timing attack vulnerabilities

## 🎯 Areas for Contribution

### High Priority
- [ ] Zero-knowledge proof integration
- [ ] Performance optimizations
- [ ] Mobile SDK development
- [ ] Cross-chain interoperability

### Medium Priority
- [ ] Web interface
- [ ] Additional demo scenarios
- [ ] Monitoring and observability
- [ ] Documentation improvements

### Good First Issues
- [ ] CLI UX improvements
- [ ] Error message enhancements
- [ ] Test coverage improvements
- [ ] Documentation updates

## 📊 Code Review Criteria

### Functionality
- [ ] Code works as intended
- [ ] Edge cases are handled
- [ ] Error handling is appropriate
- [ ] Performance is acceptable

### Quality
- [ ] Code is readable and maintainable
- [ ] Follows project conventions
- [ ] Includes appropriate tests
- [ ] Documentation is updated

### Security
- [ ] No security vulnerabilities
- [ ] Cryptographic operations are correct
- [ ] Input validation is present
- [ ] Secrets are handled properly

## 🏆 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes for significant contributions
- Annual contributor appreciation posts

## 📜 Code of Conduct

### Our Pledge
We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

## 🎉 Thank You!

Your contributions make this project better for everyone. Whether you're fixing bugs, adding features, improving documentation, or helping other users, every contribution is valuable and appreciated!

---

*This contributing guide is inspired by open source best practices and is continuously improved based on community feedback.*
