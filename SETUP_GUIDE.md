# Setup Guide - Decentralized Identity Management System

## 🚀 Quick Start

### Prerequisites
- **Rust 1.70+**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **IPFS**: For decentralized storage
- **Git**: For version control

## 📦 Installation

### 1. Install IPFS

#### Linux/macOS:
```bash
# Download and install IPFS
curl -sSL https://dist.ipfs.io/go-ipfs/v0.20.0/go-ipfs_v0.20.0_linux-amd64.tar.gz | tar -xz
sudo mv go-ipfs/ipfs /usr/local/bin/

# Initialize IPFS
ipfs init

# Start IPFS daemon (keep running in background)
ipfs daemon &
```

#### Windows:
```powershell
# Download from https://dist.ipfs.io/go-ipfs/v0.20.0/go-ipfs_v0.20.0_windows-amd64.zip
# Extract and add to PATH
ipfs init
ipfs daemon
```

### 2. Clone and Build Project

```bash
# Clone repository
git clone https://github.com/your-username/decentralized-identity-system.git
cd decentralized-identity-system

# Build all components
cargo build --release

# Run tests to verify installation
cargo test
```

## 🎯 Usage Examples

### 1. Create a DID
```bash
# Create a new DID with Ed25519 key
cargo run --bin identity-cli -- did create --method example --key-type ed25519

# Output:
# 🔑 Creating new DID...
# ✅ DID created successfully!
# 📋 DID: did:example:550e8400-e29b-41d4-a716-446655440000
# 🔐 Key Type: Ed25519VerificationKey2020
# 📦 Stored on IPFS: QmXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx
```

### 2. Issue a Verifiable Credential
```bash
# Issue a university degree credential
cargo run --bin identity-cli -- vc issue \
  --issuer "did:example:university" \
  --subject "did:example:alice" \
  --claims '{"degree": "Bachelor of Science", "major": "Computer Science", "gpa": 3.8}' \
  --credential-type "UniversityDegreeCredential"

# Output:
# 📜 Issuing new Verifiable Credential...
# ✅ Credential issued successfully!
# 📋 Credential ID: urn:uuid:123e4567-e89b-12d3-a456-426614174000
# 👤 Issuer: did:example:university
# 📦 Stored on IPFS: QmYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYyYy
```

### 3. Setup Threshold Attestation
```bash
# Setup 2-of-3 threshold scheme
cargo run --bin identity-cli -- attest setup --threshold 2 --total-parties 3

# Output:
# ⚙️  Setting up threshold attestation scheme...
# 🎯 Threshold: 2/3
# ✅ Threshold scheme setup complete!
# 🔑 Generated 3 key shares
# 📋 Scheme ID: 789e0123-e45b-67c8-d901-234567890abc
```

### 4. Run Demo Scenarios
```bash
# Run KYC demo
cargo run --bin identity-cli -- demo kyc

# Run full demo (setup + KYC)
cargo run --bin identity-cli -- demo full

# Output:
# 🎭 Running KYC Demo Scenario...
# 👤 Alice requests KYC credential
# 🏦 3 banks will verify and threshold-sign
# 📋 Alice's DID: did:example:alice-123
# 📜 KYC credential created: urn:uuid:kyc-456
# 🔄 Bank 1: Verifying... ✅ Approved
# 🔄 Bank 2: Verifying... ✅ Approved
# 🔄 Bank 3: Verifying... ❌ Declined
# 🎯 Threshold met (2/3)! Credential is valid.
# ✅ KYC Demo completed successfully!
```

## 🔧 Configuration

### IPFS Configuration
```bash
# Check IPFS status
ipfs id

# Configure IPFS for development
ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080

# Enable CORS for web applications
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["*"]'
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["PUT", "GET", "POST"]'
```

### Environment Variables
```bash
# Optional: Set custom IPFS endpoint
export IPFS_ENDPOINT="http://127.0.0.1:5001"

# Optional: Set custom Substrate endpoint
export SUBSTRATE_ENDPOINT="ws://127.0.0.1:9944"
```

## 🧪 Testing

### Run All Tests
```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration

# Specific module tests
cargo test --package identity-core
cargo test --package attestors
```

### Performance Testing
```bash
# Benchmark threshold signatures
cargo test --release threshold_benchmark -- --nocapture

# Benchmark IPFS operations
cargo test --release ipfs_benchmark -- --nocapture
```

## 🐛 Troubleshooting

### Common Issues

#### 1. IPFS Connection Failed
```bash
# Check if IPFS daemon is running
ipfs id

# If not running, start it
ipfs daemon &

# Check firewall settings
sudo ufw allow 4001
sudo ufw allow 5001
sudo ufw allow 8080
```

#### 2. Build Errors
```bash
# Update Rust toolchain
rustup update

# Clean and rebuild
cargo clean
cargo build

# Check for missing dependencies
cargo check
```

#### 3. Permission Errors
```bash
# Fix IPFS permissions
sudo chown -R $USER ~/.ipfs

# Fix cargo permissions
sudo chown -R $USER ~/.cargo
```

## 📊 Monitoring

### System Health Checks
```bash
# Check IPFS status
curl http://127.0.0.1:5001/api/v0/version

# Check system resources
cargo run --bin identity-cli -- system status

# View logs
tail -f ~/.ipfs/logs/ipfs.log
```

### Performance Metrics
```bash
# IPFS stats
ipfs stats bw
ipfs stats repo

# System metrics
cargo run --bin identity-cli -- metrics
```

## 🔒 Security Considerations

### Development Environment
- Use test networks only
- Generate new keys for each test
- Never commit private keys to version control
- Use environment variables for sensitive configuration

### Production Deployment
- Use hardware security modules (HSMs) for key storage
- Implement proper key rotation policies
- Set up monitoring and alerting
- Use TLS for all network communications
- Implement rate limiting and DDoS protection

## 🌐 Network Configuration

### Local Development
```bash
# Start local Substrate node (if using)
substrate --dev --tmp

# Configure local IPFS cluster
ipfs-cluster-service init
ipfs-cluster-service daemon
```

### Production Network
```bash
# Connect to production IPFS network
ipfs bootstrap add /ip4/production-node-ip/tcp/4001/p2p/peer-id

# Configure Substrate connection
export SUBSTRATE_ENDPOINT="wss://production-substrate-node:9944"
```

## 📚 Additional Resources

### Documentation
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [IPFS Documentation](https://docs.ipfs.io/)
- [Substrate Documentation](https://docs.substrate.io/)

### Contributing
- Read [CONTRIBUTING.md](CONTRIBUTING.md)
- Submit pull requests with tests
- Report bugs with detailed reproduction steps

## 🎓 Learning Path

### Beginner
1. Understand DID and VC concepts
2. Run basic CLI commands
3. Explore demo scenarios
4. Read project structure documentation

### Intermediate
1. Implement custom verifiers
2. Create new credential types
3. Integrate with existing systems
4. Contribute to codebase

### Advanced
1. Implement zero-knowledge proofs
2. Design custom consensus mechanisms
3. Optimize performance and scalability
4. Research new cryptographic primitives
