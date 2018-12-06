# Research

This repository implements cryptographic research in javascript/solidity that we kinda thought we would use. But don't. Yet?

- [x] [Hacky Secp256k1 ecMull and ecAdd](https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/10) - necessary for doing secp256k1 calculations efficiently on-chain
- [x] Schnorr Signature + Verification (secp256k1)
- [x] Schnorr Signature Verification On-Chain (secp256k1)
- [x] Schnorr Blind Signatures (secp256k1)
- [ ] Schnorr Blind Signature Verification On-Chain (secp256k1)
- [x] Schnorr Ring Signatures (secp256k1)
- [ ] Schnorr Ring Signature Verification On-Chain (secp256k1)
- [x] Designated Verifier Signatures (secp256k1)
- [ ] Designated Verifier Signature Verification On-Chain (secp256k1)

On-chain verification exists for altbn128 on the altbn128 branch.