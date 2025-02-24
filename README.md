# Bitcoin-frost-wallet 🥶

A high-performance, secure implementation of FROST (Flexible Round-Optimized Schnorr Threshold) signatures with ChillDKG for Bitcoin wallets in Rust.

## Why Bitcoin-frost-wallet?

Traditional Bitcoin wallets rely on single-signature schemes or complex multi-signature setups. Bitcoin-frost-wallet brings threshold signatures to Bitcoin wallets, enabling:

- **Distributed Key Generation**: No single point of failure in key generation
- **Flexible Signing**: Any t-of-n parties can sign transactions
- **Enhanced Security**: No single party ever holds the complete private key
- **Schnorr Compatibility**: Native support for Bitcoin's Schnorr signatures
- **Performance**: Optimized Rust implementation with parallel computation support

## Project Goals

- Provide a production-ready FROST implementation for Bitcoin
- Enable easy integration with existing Bitcoin wallets
- Maintain high security standards with comprehensive testing
- Support both synchronous and asynchronous signing protocols
- Minimize communication rounds for better performance

## Features

- ✨ ChillDKG (Distributed Key Generation)
- 🔐 Threshold Schnorr signatures (t-of-n)
- ⚡ Parallel signature computation
- 🧪 Comprehensive test suite
- 📊 Performance benchmarking
- 🔧 Configurable threshold parameters

## Getting Started


## Documentation


## Benchmarks


## Security Considerations

- This implementation follows the [FROST paper](https://eprint.iacr.org/2020/852.pdf)
- Regular security audits are planned
- Side-channel attack mitigations are in place
- Bug bounty program coming soon

## Contributing

Contributions are welcome! Please check out our:

1. [Contributing Guidelines](CONTRIBUTING.md)
2. [Code of Conduct](CODE_OF_CONDUCT.md)
3. [Security Policy](SECURITY.md)

Areas we're particularly interested in:
- Performance optimizations
- Additional test coverage
- Documentation improvements
- Security analysis

## License
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Acknowledgments

This project builds upon:
- [The FROST paper](https://eprint.iacr.org/2020/852.pdf) by Chelsea Komlo and Ian Goldberg
- [The ChillDKG paper](https://eprint.iacr.org/2023/058.pdf) by Omer Shlomovits and István András Seres
- [k256](https://github.com/RustCrypto/elliptic-curves) by RustCrypto