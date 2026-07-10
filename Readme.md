# IDPS — Intrusion Detection & Prevention System

A lightweight, extensible Intrusion Detection and Prevention System (IDPS) for monitoring network traffic and host activity, detecting malicious behavior, and automatically responding to threats in real time.

## Overview

This IDPS combines **signature-based** and **anomaly-based** detection to identify known attack patterns and unusual behavior across network and host layers. When a threat is detected, the system can alert, log, or actively block malicious traffic depending on configured response policy.

## Features

- **Network-based detection (NIDS)** — inspects live packet traffic against rule sets
- **Host-based detection (HIDS)** — monitors system logs, file integrity, and process activity
- **Signature matching** — rule-based detection using a customizable ruleset (e.g. Snort/Suricata-style rules)
- **Anomaly detection** — statistical/ML-based baseline modeling to flag deviations
- **Prevention mode** — active blocking (firewall/iptables integration) in addition to passive alerting
- **Alerting** — configurable outputs (console, syslog, email, webhook/SIEM integration)
- **Dashboard/UI** — real-time visibility into alerts, traffic, and system health
- **Logging & audit trail** — structured logs for forensic analysis

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│  Packet /    │ --> │  Detection    │ --> │  Response       │
│  Log Capture │     │  Engine       │     │  Engine         │
└─────────────┘     └──────────────┘     └────────────────┘
                            │
                            v
                     ┌──────────────┐
                     │  Alerting /   │
                     │  Logging      │
                     └──────────────┘
```

- **Capture Module** — sniffs network interfaces (via libpcap/npcap) or tails host logs
- **Detection Engine** — runs signature and anomaly detectors against captured data
- **Response Engine** — executes configured actions (alert / drop / block)
- **Storage** — persists events, alerts, and metrics for review

## Requirements

- OS: Linux (recommended) / Windows / macOS
- Runtime: [language/runtime — e.g. Python 3.10+, Go 1.21+]
- Privileges: root/administrator (required for raw packet capture)
- Dependencies: see `requirements.txt` / `go.mod` / `package.json`

## Installation

```bash
# Clone the repository
git clone https://github.com/<org>/<idps-repo>.git
cd <idps-repo>

# Install dependencies
<pip install -r requirements.txt>   # or equivalent for your stack

# Copy and edit the example configuration
cp config/config.example.yaml config/config.yaml
```

## Configuration

Edit `config/config.yaml` to define:

| Setting | Description |
|---|---|
| `interface` | Network interface to monitor (e.g. `eth0`) |
| `mode` | `detect` (IDS only) or `prevent` (IPS, active blocking) |
| `rules_path` | Path to signature ruleset directory |
| `alerting.channels` | Where alerts are sent (console, syslog, email, webhook) |
| `logging.level` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `anomaly.enabled` | Toggle anomaly-based detection |

## Usage

```bash
# Run in detection-only mode
./idps run --mode detect --config config/config.yaml

# Run in prevention mode (requires elevated privileges)
sudo ./idps run --mode prevent --config config/config.yaml

# Validate ruleset without starting the engine
./idps rules validate --path rules/
```

## Rule Format

Custom detection rules live under `rules/` and follow a simple pattern:

```
alert tcp any any -> any 22 (msg:"Possible SSH brute force"; threshold: type both, track by_src, count 5, seconds 60; sid:1000001;)
```

## Roadmap

- [ ] Machine-learning-based anomaly scoring
- [ ] Cloud/container-native deployment (Docker, Kubernetes)
- [ ] SIEM integrations (Splunk, ELK, QRadar)
- [ ] Distributed sensor architecture with central management

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a pull request.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Open a pull request

## License

[Specify license — e.g. MIT, Apache 2.0]

## Disclaimer

This software is intended for use on networks and systems you own or are authorized to monitor. Unauthorized use against systems you do not control may be illegal.
