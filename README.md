# DKIM Key Exploitation Research Tool

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📜 Overview

This is a **research and educational** tool demonstrating potential vulnerabilities in DomainKeys Identified Mail (DKIM) implementations using weak RSA key sizes. It performs the following operations:

1. **Fetches the DKIM public key** from DNS.
2. **Attempts to factor the RSA key** using quantum-inspired algorithms via Q#.
3. **Derives the private key** from the factorized components.
4. **Generates and sends a DKIM-signed email** using the derived private key.

> ⚠️ **Disclaimer**: This project is intended solely for **academic research** and **security education**. Unauthorized use of this software to access or impersonate others is strictly prohibited and may be illegal. Always obtain explicit permission before testing this on any domain.

---

## 🚀 Features

- DNS-based DKIM public key retrieval
- RSA modulus factorization using Q# algorithms
- Private key reconstruction in C#
- Email signing and sending with forged DKIM headers
- Modular architecture for custom extension and experimentation

---

## 🧪 Technologies Used

- **C#** – Core application logic
- **Q#** – RSA factorization routines
- **.NET SDK** – Multi-platform development
- **System.Net.Mail** – Email sending functionality
- **DnsClient.NET** – DNS lookups

---

## 🛠️ Installation

### Prerequisites

- [.NET 9+ SDK](https://dotnet.microsoft.com/en-us/download)
- [QDK (Quantum Development Kit)](https://learn.microsoft.com/en-us/azure/quantum/install-overview-qdk)
- A DKIM-enabled domain and selector (e.g., 2048-bit RSA key)

### Clone the Repository

```bash
git clone https://github.com/billvolz/quantum-email.git
cd dkim-key-exploit-tool
