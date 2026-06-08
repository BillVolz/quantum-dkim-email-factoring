# DKIM Key Exploitation Research Tool

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## Disclaimer and Legal Notice

> **This project is strictly theoretical and academic. It is not a working attack tool.**

This repository demonstrates DomainKeys Identified Mail (DKIM) RSA factorization using Shor's quantum algorithm, implemented in Q# and C#. It exists for **educational and research purposes only** — specifically to illustrate how quantum computing *would* threaten RSA-based cryptography if sufficiently large fault-tolerant quantum hardware existed.

**It does not work against real RSA keys today, and will not for the foreseeable future.** Breaking RSA-1024 requires approximately 30 million physical qubits with error correction. The largest quantum computers available as of 2025 have ~1,000 physical qubits. The gap is not incremental — it represents decades of engineering progress that has not yet occurred.

By using, modifying, or distributing this software, you agree that:

- You will only test against domains and systems you own or have **explicit written permission** to test.
- You will not use this software to impersonate, defraud, or harm any person or organization.
- Unauthorized use to access, compromise, or impersonate others may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, the EU Network and Information Security Directive, and equivalent laws in your jurisdiction.

**The authors and contributors accept no responsibility or liability for any misuse of this software.** If you are not certain you have authorization to test a given domain, you do not have authorization.

---

## Overview

This tool performs the following steps — partly quantum, partly classical, fully demonstrative:

1. **Fetches the DKIM public key** from DNS for a configured domain and selector.
2. **Runs Shor's period-finding circuit** via Q# (currently on `N=15` as a simulator-scale test).
3. **Applies classical post-processing** (continued fractions) in C# to extract the period from QFT measurements.
4. **Falls back to classical Pollard's rho** to factor the real RSA modulus (since the simulator can't handle RSA-scale inputs).
5. **Derives the private key** from the factored primes.
6. **Generates and sends a DKIM-signed email** using the derived private key.

---

## Features

- DNS-based DKIM public key retrieval
- RSA modulus factorization using Q# Shor's algorithm — supports **arbitrary-precision (BigInt) inputs**
- Classical fallback factorization using **Pollard's rho** (O(n^1/4))
- All classical post-processing (continued fractions, period verification, retry loop) handled in C# — no quantum-side classical control flow, making the circuit compatible with Quantinuum hardware targets
- Private key reconstruction in C#
- Email signing and sending with forged DKIM headers
- Modular architecture for custom extension and experimentation

---

## Technologies Used

- **C#** – Core application logic and classical post-processing
- **Q#** – RSA factorization routines (Shor's algorithm with BigInt arithmetic)
- **.NET 9 SDK** – Multi-platform development
- **System.Net.Mail** – Email sending functionality
- **DnsClient.NET** – DNS lookups
- **Microsoft.Azure.Quantum.Client** – Azure Quantum workspace integration

---

## Current Status

### Quantum path (Q# / Shor's algorithm)

The Q# implementation is **algorithmically complete, hardware-compatible, and builds cleanly** against the `quantinuum.qpu.h1-1` execution target:

- All Q# operations use `BigInt` — no 32/64-bit integer overflow
- `QuantumMultiplyByModulus` uses bit-decomposition O(log a) additions instead of O(a)
- `QuantumExponentForPeriodFinding` uses repeated squaring instead of iterated multiplication
- Adjoint and Controlled specializations are all correctly derived (via `BitDecompFactors` Q# function — no `set`-statements in Adj+Ctl operations)
- No hardware-restricted intrinsics (`ResultArrayAsBoolArray` removed)
- Circuit returns raw `Result[]`; all classical work (continued fractions, period verification, retry loop) is in C#

**Simulator only for now**: `QuantumSimulator` caps at ~30 qubits. The quantum path is exercised with `N=15, a=2`. Factoring RSA-1024 requires ~3,000 logical qubits (~30 million physical) — hardware that does not yet exist.

### Classical fallback (C#)

`FactorizeModulus` uses **Pollard's rho** (O(n^1/4)). Still infeasible for RSA-1024 (~2^256 operations), but correct and fast for sub-64-bit moduli.

---

## What's Needed to Run on Real RSA Keys

The three hardware-compatibility changes (QS5027, ExecutionTarget, Azure Quantum submission) have been implemented. Two small code changes remain before this could run on a real RSA key — both are in `Program.cs`:

### 1. Point the quantum circuit at the real modulus

```csharp
// Currently in Program.cs — change these:
System.Numerics.BigInteger qnum = 15;  // test value
System.Numerics.BigInteger qa = 2;     // test value

// To:
qnum = n;            // the real RSA modulus from the DKIM key
qa = PickCoprime(n); // a random a with gcd(a, n) == 1
```

### 2. Implement `PickCoprime`

```csharp
static BigInteger PickCoprime(BigInteger n)
{
    var rng = RandomNumberGenerator.Create();
    while (true)
    {
        var bytes = new byte[n.GetByteCount()];
        rng.GetBytes(bytes);
        var a = new BigInteger(bytes, isUnsigned: true) % (n - 2) + 2;
        if (BigInteger.GreatestCommonDivisor(a, n) == 1) return a;
    }
}
```

Note: if `gcd(a, n) != 1` you have accidentally found a prime factor of `n` directly — an early exit worth checking for before the quantum circuit runs.

### To target Azure Quantum (Quantinuum H1-1)

Set four environment variables before running, and authenticate with `az login`:

```
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_RESOURCE_GROUP=<your-resource-group>
AZURE_WORKSPACE_NAME=<your-workspace-name>
AZURE_LOCATION=eastus
```

The machine selection is already conditional in `Program.cs` — if `AZURE_WORKSPACE_NAME` is set, the program submits to Quantinuum H1-1; otherwise it runs the local simulator.

---

## Hardware Gap — Why This Cannot Work Today

Factoring cryptographically relevant RSA keys requires fault-tolerant quantum hardware that does not yet exist.

### Qubit requirements

| RSA key size | Logical qubits needed | Physical qubits (with error correction) |
|---|---|---|
| RSA-512 | ~1,500 | ~15 million |
| RSA-1024 | ~3,000 | ~30 million |
| RSA-2048 | ~6,000 | ~60 million |

### State of the art (2025)

| System | Physical qubits | Notes |
|---|---|---|
| IBM Heron | ~1,000 | Best superconducting qubit count |
| Google Willow | 105 | High-fidelity demonstration chip |
| Quantinuum H1-1 | 20 | Best gate fidelity available; this project's hardware target |

The gap between "best available" and "RSA-1024 capable" is not incremental. It requires:

- **Error correction at scale**: approximately 1,000 physical qubits per logical qubit, sustained across millions of gate operations
- **Fault-tolerant architecture**: surface codes or similar, requiring hardware that does not exist in volume
- **Engineering maturity**: decades of progress in fabrication, control electronics, and cryogenics

The classical record for RSA factorization is RSA-250 (829 bits), factored in 2020 using the General Number Field Sieve on classical supercomputers — without any quantum hardware.

**Realistic timeline**: Most credible estimates place cryptographically relevant quantum computers (capable of breaking RSA-2048) in the 2030–2040 range at the earliest, assuming continued exponential progress in qubit counts and error rates. Some estimates extend further.

This means RSA-based DKIM keys are **not at immediate quantum risk**. Organizations concerned about post-quantum cryptography should monitor NIST's post-quantum cryptography standardization effort (FIPS 203/204/205) rather than treat this as an imminent threat.

---

## Installation

### Prerequisites

- [.NET 9+ SDK](https://dotnet.microsoft.com/en-us/download)
- [QDK (Quantum Development Kit) 0.28+](https://learn.microsoft.com/en-us/azure/quantum/install-overview-qdk)
- A DKIM-enabled domain and selector for testing

### Clone the Repository

```bash
git clone https://github.com/billvolz/quantum-email.git
cd quantum-email
```

### Build

```bash
cd src/QuantumEmail
dotnet build

cd ../QuantumEmail.Host
dotnet build
```

### Run (simulator)

The quantum path runs `N=15, a=2` on the local `QuantumSimulator`. To test against a real DKIM key, update `mailDomain` and `mailSelector` in `Program.cs`.

```bash
cd src/QuantumEmail.Host
dotnet run
```

---

## License

MIT
