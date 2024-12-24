# BBS+ Signature Verifier Smart Contract
## Warning!!!
This is a research project, and the smart contract may contain vulnerabilities. Please do not use it in production without testing and/or auditing!
## Overview
This repo contains the solidity implementation of the BBS+ Signature Verification compatible with [this](https://github.com/hashcloak/bbs_sign) BBS+ signature implementation over BN254 pairing curve. Since the This implementation harcodes 32(fixed) randomly sampled points from the G1 subgroup, therefore it supports the verification of upto 32-1 = 31 messages.

- To build: `forge build --via-ir`
- Run test: `forge test --via-ir`
