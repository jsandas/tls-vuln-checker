# tls-vuln-checker

[![Integration Tests](https://github.com/jsandas/tls-vuln-checker/actions/workflows/integration.yml/badge.svg)](https://github.com/jsandas/tls-vuln-checker/actions/workflows/integration.yml)
[![Code Tests](https://github.com/jsandas/tls-vuln-checker/actions/workflows/code.yml/badge.svg)](https://github.com/jsandas/tls-vuln-checker/actions/workflows/code.yml)
[![Quality Checks](https://github.com/jsandas/tls-vuln-checker/actions/workflows/quality.yml/badge.svg)](https://github.com/jsandas/tls-vuln-checker/actions/workflows/quality.yml)
[![CodeCov](https://codecov.io/gh/jsandas/tls-vuln-checker/graph/badge.svg?token=S2805SVWX4)](https://codecov.io/gh/jsandas/tls-vuln-checker)
[![GoDoc](https://godoc.org/github.com/jsandas/tls-vuln-checker?status.svg)](https://godoc.org/github.com/jsandas/tls-vuln-checker)

A Go module for checking whether a TLS-enabled service is vulnerable to several well-known protocol and implementation flaws. The project provides small, focused checks that can be used by security researchers, operators, and developers to quickly assess servers without building a custom test harness from scratch.

## Purpose

This library is designed to help answer a simple question: is this server likely affected by a known TLS vulnerability? It does that by opening a connection to a target host and port, performing the required handshake or upgrade step, and then sending crafted probes that are specific to the vulnerability being tested.

The implementation is intentionally modular, so each check can be used independently. It also relies on the starttls-go package to handle STARTTLS-style upgrades when the target service requires them.

## Features

- Focused checks for common TLS vulnerabilities
- Structured result objects with clear status values
- Minimal dependencies and straightforward Go API
- Built-in support for timeout-based network checks
- Unit and integration test coverage for both vulnerable and non-vulnerable behavior

## Implemented Vulnerability Checks

### CCS Injection

Checks for the OpenSSL CCS Injection vulnerability (CVE-2014-0224) by initiating a TLS connection, completing the handshake up to the appropriate stage, and sending crafted ChangeCipherSpec messages to see whether the server mishandles the exchange.

### Heartbleed

Tests for the Heartbleed vulnerability (CVE-2014-0160) by probing for TLS heartbeat support and sending a malformed heartbeat request to determine whether the server responds with more data than it should.

### Debian Weak Key

Detects weak Debian/OpenSSL key material (CVE-2008-0166) by comparing a certificate modulus against known weak-key blacklists for common RSA key sizes.

> **Note**: This check requires blacklist files to be present at `resources/weakkeys/` (relative to the working directory) or at the path specified by the `WEAKKEY_PATH` environment variable. Run `make setup-local` to download the blacklist files before using this check.

## Installation

```bash
go get github.com/jsandas/tls-vuln-checker
```

## Usage

Each vulnerability check is exposed as a small Go type with a `Check` method.

Current APIs:

- `ccs.CCSInjection.Check(host, port)` sets `Vulnerable` to `yes`, `no`, or `error`.
- `heartbleed.Heartbleed.Check(host, port, tlsVers)` sets `Vulnerable` and `ExtensionEnabled`.
- `debianweakkey.DebianWeakKey.Check(keysize, modulus)` sets `Vulnerable` to `yes`, `no`, `error`, or `uncommonKey` for unsupported key sizes.

```go
package main

import (
    "fmt"

    "github.com/jsandas/tls-vuln-checker/vulnerabilities/ccs"
    "github.com/jsandas/tls-vuln-checker/vulnerabilities/heartbleed"
    "github.com/jsandas/tls-vuln-checker/vulnerabilities/debianweakkey"
)

func main() {
    ccsCheck := &ccs.CCSInjection{}
    if err := ccsCheck.Check("example.com", "443"); err != nil {
        fmt.Println("CCS check failed:", err)
    } else {
        fmt.Printf("CCS vulnerable? %s\n", ccsCheck.Vulnerable)
    }

    hbCheck := &heartbleed.Heartbleed{}
    if err := hbCheck.Check("example.com", "443", 771); err != nil {
        fmt.Println("Heartbleed check failed:", err)
    } else {
        fmt.Printf("Heartbleed vulnerable? %s\n", hbCheck.Vulnerable)
        fmt.Printf("Heartbeat extension enabled? %v\n", hbCheck.ExtensionEnabled)
    }

    weakKeyCheck := &debianweakkey.DebianWeakKey{}
    if err := weakKeyCheck.Check(2048, "<certificate-modulus>"); err != nil {
        fmt.Println("Weak key check failed:", err)
    } else {
        fmt.Printf("Weak key vulnerable? %s\n", weakKeyCheck.Vulnerable)
    }
}
```

## Security Considerations

1. Use these checks responsibly and only against systems you own or are authorized to test.
2. Follow the principle of least privilege when running probes against production services.
3. Always confirm results with additional validation and remediation steps where appropriate.

## Contributing

Contributions are welcome. Please feel free to submit a pull request or open an issue if you have suggestions, bug reports, or improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

This project builds on the excellent Go ecosystem and on the starttls-go package for the STARTTLS upgrade handling used by several checks.