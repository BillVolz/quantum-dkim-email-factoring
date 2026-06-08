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

This tool performs the following steps:

1. **Fetches the DKIM public key** from DNS for a configured domain and selector.
2. **Runs Shor's period-finding circuit** via Q# (on `N=15` as a simulator-scale demonstration).
3. **Applies classical post-processing** (continued fractions) in C# to extract the period from QFT measurements.
4. **Falls back to classical Pollard's rho** to factor the real RSA modulus for the demo (the simulator cannot handle RSA-scale inputs).
5. **Derives the private key** from the factored primes.
6. **Generates and sends a DKIM-signed email** using the derived private key.

---

## Technologies Used

- **C#** – Core application logic and classical post-processing
- **Q#** – Shor's algorithm circuit (BigInt arithmetic throughout)
- **.NET 9 SDK**
- **DnsClient.NET** – DNS lookups
- **Microsoft.Azure.Quantum.Client** – Azure Quantum workspace integration

---

## Features

- DNS-based DKIM public key retrieval
- RSA modulus factorization using Q# Shor's algorithm — supports arbitrary-precision (BigInt) inputs
- Probabilistic retry loop with classical continued-fraction post-processing (all in C#)
- Classical fallback factorization using Pollard's rho (O(n^1/4))
- Private key reconstruction and encrypt/decrypt demonstration
- Email signing and sending with forged DKIM headers
- Azure Quantum integration — targets Quantinuum H1-1 when credentials are present, local simulator otherwise

---

## How It Works

### Quantum circuit (Q#)

The Q# circuit implements Shor's period-finding algorithm:

- Prepares a superposition over the x-register, applies modular exponentiation `|x⟩|0⟩ → |x⟩|a^x mod N⟩`, measures the y-register to collapse entanglement, applies the QFT, then returns the raw x-register measurements as `Result[]`.
- Uses arbitrary-precision `BigInt` throughout — no 32/64-bit overflow at any input size.
- All classical post-processing runs in C#, making the circuit compatible with Quantinuum hardware targets (no classical control flow conditioned on measurement results inside Q#).

### Classical post-processing (C#)

The C# host applies continued-fraction expansion to the QFT measurement output to find period candidates, then verifies each candidate with `a^r mod N == 1`. Because the algorithm is probabilistic, the host retries up to 20 times before giving up.

### Classical factoring fallback

`FactorizeModulus` uses Pollard's rho (O(n^1/4)) with a per-polynomial iteration cap to stay responsive. It is used for the demo because the local simulator cannot run circuits large enough for real RSA keys.

---

## Limitations

### Simulator scale

`QuantumSimulator` supports approximately 30 qubits. The period-finding circuit for an n-bit modulus requires `3n` qubits, so the simulator can only demonstrate the algorithm on small inputs. The project runs `N=15, a=2` by default.

### Classical fallback is also infeasible for real keys

Pollard's rho requires O(n^1/4) operations. For RSA-1024 that is approximately 2^256 operations — computationally infeasible on any classical hardware.

### Hardware gap

Factoring cryptographically relevant RSA keys requires fault-tolerant quantum hardware that does not yet exist:

| RSA key size | Logical qubits needed | Physical qubits (estimated) |
|---|---|---|
| RSA-512 | ~1,500 | ~15 million |
| RSA-1024 | ~3,000 | ~30 million |
| RSA-2048 | ~6,000 | ~60 million |

Current state of the art (2025):

| System | Physical qubits | Notes |
|---|---|---|
| IBM Heron | ~1,000 | Best superconducting qubit count |
| Google Willow | 105 | High-fidelity demonstration chip |
| Quantinuum H1-1 | 20 | Best gate fidelity; this project's hardware target |

Bridging this gap requires approximately 1,000 physical qubits per logical qubit with sustained error correction across millions of gate operations. Most credible estimates place cryptographically relevant quantum computers in the **2030–2040 range at the earliest**.

The classical record is RSA-250 (829 bits), factored in 2020 using the General Number Field Sieve on classical supercomputers.

RSA-based DKIM keys are **not at immediate quantum risk**. Organizations planning for post-quantum cryptography should follow NIST's standardized algorithms (FIPS 203/204/205).

---

## Running Against Real RSA Keys (When Hardware Exists)

Two lines in `Program.cs` switch the quantum path from the demo values to a real RSA modulus:

```csharp
// Uncomment these two lines:
// qnum = n;
// qa = BigintegerMath.PickCoprime(n);
```

`PickCoprime` is already implemented — it picks a random `a` with `gcd(a, n) == 1`, with an early-exit check in case the chosen `a` already reveals a factor directly.

### Targeting Azure Quantum (Quantinuum H1-1)

Set four environment variables before running and authenticate with `az login`:

```
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_RESOURCE_GROUP=<your-resource-group>
AZURE_WORKSPACE_NAME=<your-workspace-name>
AZURE_LOCATION=eastus
```

When `AZURE_WORKSPACE_NAME` is set, the program submits to Quantinuum H1-1 via Azure Quantum. Otherwise it runs on the local simulator.

---

## Installation

### Prerequisites

- [.NET 9+ SDK](https://dotnet.microsoft.com/en-us/download)
- [QDK (Quantum Development Kit) 0.28+](https://learn.microsoft.com/en-us/azure/quantum/install-overview-qdk)
- A DKIM-enabled domain and selector for testing

### Clone

```bash
git clone https://github.com/billvolz/quantum-email.git
cd quantum-email
```

### Build

```bash
cd src/QuantumEmail && dotnet build
cd ../QuantumEmail.Host && dotnet build
```

### Run

```bash
cd src/QuantumEmail.Host
dotnet run
```

Update `mailDomain` and `mailSelector` in `Program.cs` to test against a specific DKIM key.

---

## License

MIT
