# OpenCTI AssemblyLine Import Connector

![OpenCTI](https://img.shields.io/badge/OpenCTI-6.x-blue)
![AssemblyLine](https://img.shields.io/badge/AssemblyLine-4.x-green)
![License](https://img.shields.io/badge/License-Apache%202.0-yellow)
![Python](https://img.shields.io/badge/Python-3.11+-brightgreen)

External import connector for OpenCTI that automatically imports malicious file analysis results from [AssemblyLine](https://cybercentrecanada.github.io/assemblyline4_docs/) into OpenCTI.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Objects Created](#objects-created)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

This connector periodically queries AssemblyLine for malicious file submissions and imports the analysis results into OpenCTI. It creates a comprehensive threat intelligence picture by:

- Creating file artifacts with full hash information
- Extracting and creating indicators for malicious IOCs (domains, IPs, URLs)
- Creating corresponding observables for correlation with logs
- Generating Malware Analysis objects (visible in OpenCTI's dedicated section)
- Extracting MITRE ATT&CK techniques
- Identifying malware families
- Linking related artifacts

This connector is inspired by the Hybrid Analysis connector and provides similar functionality for AssemblyLine users.

## Features

### Core Features

| Feature | Description |
|---------|-------------|
| **Malware Analysis Objects** | Creates STIX 2.1 Malware Analysis SDOs that appear in OpenCTI's "Malware Analysis" section |
| **Indicators Creation** | Automatically creates indicators for malicious domains, IPs, and URLs |
| **Observables Creation** | Creates corresponding observables with "based-on" relationships to indicators |
| **MITRE ATT&CK Mapping** | Extracts and creates Attack Patterns from AssemblyLine's attack_matrix |
| **Malware Families** | Identifies and creates Malware entities for detected families |
| **Artifact Linking** | Links newly imported files with existing artifacts in OpenCTI |
| **TLP Support** | Configurable TLP marking for all created objects |
| **AssemblyLine Attribution** | All objects are attributed to "AssemblyLine" identity |

### What Gets Created

```
AssemblyLine Submission
    │
    ├── 📁 Artifact/StixFile (analyzed file)
    │       │
    │       ├── related-to → 🎯 Indicator (Domain)
    │       │                    └── based-on → 🔍 Observable (Domain-Name)
    │       │
    │       ├── related-to → 🎯 Indicator (IP)
    │       │                    └── based-on → 🔍 Observable (IPv4-Addr)
    │       │
    │       ├── related-to → 🎯 Indicator (URL)
    │       │                    └── based-on → 🔍 Observable (Url)
    │       │
    │       ├── related-to → 🦠 Malware Family
    │       │
    │       └── uses → ⚔️ Attack Pattern (MITRE ATT&CK)
    │
    └── 🔬 Malware Analysis (dedicated section)
            └── analysis_sco_refs → [file, domains, IPs, URLs]
```

## Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│                     │     │                      │     │                     │
│    AssemblyLine     │────▶│  Import Connector    │────▶│      OpenCTI        │
│                     │     │                      │     │                     │
│  ┌───────────────┐  │     │  ┌────────────────┐  │     │  ┌───────────────┐  │
│  │  Submissions  │  │     │  │ Query API      │  │     │  │  Artifacts    │  │
│  │  with score   │  │     │  │ Extract IOCs   │  │     │  │  Indicators   │  │
│  │  >= 1000      │  │     │  │ Extract ATT&CK │  │     │  │  Observables  │  │
│  └───────────────┘  │     │  │ Create STIX    │  │     │  │  Malware      │  │
│                     │     │  └────────────────┘  │     │  │  ATT&CK       │  │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
```

## Requirements

- **OpenCTI** >= 6.0.0
- **AssemblyLine** >= 4.0
- **Python** >= 3.11
- **Docker** (recommended for deployment)

### Python Dependencies

```
pycti>=6.0.0
assemblyline-client>=4.0.0
stix2>=3.0.0
pyyaml>=6.0
```

## Installation

### Option 1: Docker Compose (Recommended)

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/opencti-assemblyline-import.git
cd opencti-assemblyline-import
```

2. **Create environment file**

```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Add to your OpenCTI docker-compose.yml**

```yaml
connector-assemblyline-import:
  image: opencti/connector-assemblyline-import:latest
  build:
    context: ./assemblyline-import
    dockerfile: Dockerfile
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=${ASSEMBLYLINE_IMPORT_CONNECTOR_ID}
    - CONNECTOR_TYPE=EXTERNAL_IMPORT
    - CONNECTOR_NAME=AssemblyLine Import
    - CONNECTOR_SCOPE=assemblyline
    - CONNECTOR_AUTO=true
    - CONNECTOR_CONFIDENCE_LEVEL=80
    - CONNECTOR_LOG_LEVEL=info
    - ASSEMBLYLINE_URL=${ASSEMBLYLINE_URL}
    - ASSEMBLYLINE_USER=${ASSEMBLYLINE_USER}
    - ASSEMBLYLINE_APIKEY=${ASSEMBLYLINE_APIKEY}
    - ASSEMBLYLINE_VERIFY_SSL=false
    - ASSEMBLYLINE_IMPORT_INTERVAL=240
    - ASSEMBLYLINE_LOOKBACK_DAYS=1
    - ASSEMBLYLINE_TLP_LEVEL=TLP:AMBER
    - ASSEMBLYLINE_CREATE_NETWORK_INDICATORS=true
    - ASSEMBLYLINE_CREATE_OBSERVABLES=true
    - ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS=true
    - ASSEMBLYLINE_CREATE_MALWARE_ENTITIES=true
    - ASSEMBLYLINE_CREATE_ATTACK_PATTERNS=true
    - ASSEMBLYLINE_INCLUDE_SUSPICIOUS=false
    - ASSEMBLYLINE_CREATE_AS_ARTIFACT=true
  restart: always
  depends_on:
    - opencti
  networks:
    - opencti
```

4. **Deploy**

```bash
docker-compose up -d connector-assemblyline-import
```

### Option 2: Manual Installation

1. **Clone and install dependencies**

```bash
git clone https://github.com/yourusername/opencti-assemblyline-import.git
cd opencti-assemblyline-import
pip install -r requirements.txt
```

2. **Configure**

```bash
cp config.yml.example config.yml
# Edit config.yml with your settings
```

3. **Run**

```bash
python assemblyline_import.py
```

## Configuration

### Environment Variables

#### OpenCTI Connection

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCTI_URL` | Yes | - | OpenCTI platform URL |
| `OPENCTI_TOKEN` | Yes | - | OpenCTI API token |

#### Connector Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CONNECTOR_ID` | Yes | - | Unique connector UUID (v4) |
| `CONNECTOR_TYPE` | Yes | `EXTERNAL_IMPORT` | Connector type |
| `CONNECTOR_NAME` | Yes | `AssemblyLine Import` | Display name in OpenCTI |
| `CONNECTOR_SCOPE` | Yes | `assemblyline` | Connector scope |
| `CONNECTOR_AUTO` | No | `true` | Auto-start connector |
| `CONNECTOR_CONFIDENCE_LEVEL` | No | `80` | Confidence level (0-100) |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Log level (debug/info/warning/error) |

#### AssemblyLine Connection

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ASSEMBLYLINE_URL` | Yes | - | AssemblyLine instance URL |
| `ASSEMBLYLINE_USER` | Yes | - | AssemblyLine username |
| `ASSEMBLYLINE_APIKEY` | Yes | - | AssemblyLine API key |
| `ASSEMBLYLINE_VERIFY_SSL` | No | `true` | Verify SSL certificates |

#### Import Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ASSEMBLYLINE_IMPORT_INTERVAL` | No | `240` | Import interval in seconds |
| `ASSEMBLYLINE_LOOKBACK_DAYS` | No | `1` | Days to look back for submissions |
| `ASSEMBLYLINE_TLP_LEVEL` | No | `TLP:WHITE` | TLP marking (RED/AMBER/GREEN/WHITE/CLEAR) |
| `ASSEMBLYLINE_INCLUDE_SUSPICIOUS` | No | `false` | Include suspicious IOCs (not just malicious) |

#### Feature Toggles

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ASSEMBLYLINE_CREATE_NETWORK_INDICATORS` | No | `true` | Create indicators for domains/IPs/URLs |
| `ASSEMBLYLINE_CREATE_OBSERVABLES` | No | `true` | Create observables with based-on relationships |
| `ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS` | No | `true` | Create Malware Analysis objects |
| `ASSEMBLYLINE_CREATE_MALWARE_ENTITIES` | No | `true` | Create Malware family entities |
| `ASSEMBLYLINE_CREATE_ATTACK_PATTERNS` | No | `true` | Create MITRE ATT&CK patterns |
| `ASSEMBLYLINE_CREATE_AS_ARTIFACT` | No | `true` | Create files as Artifacts (false = StixFile) |

### Configuration File (config.yml)

```yaml
opencti:
  url: 'http://opencti:8080'
  token: 'your-opencti-token'

connector:
  id: 'your-connector-uuid'
  type: 'EXTERNAL_IMPORT'
  name: 'AssemblyLine Import'
  scope: 'assemblyline'
  auto: true
  confidence_level: 80
  log_level: 'info'

assemblyline_import:
  assemblyline_url: 'https://your-assemblyline-instance'
  assemblyline_user: 'opencti-connector'
  assemblyline_apikey: 'your-api-key'
  assemblyline_verify_ssl: false
  interval: 240
  lookback_days: 1
  tlp_level: 'TLP:AMBER'
  include_suspicious: false

assemblyline:
  create_network_indicators: true
  create_observables: true
  create_malware_analysis: true
  create_malware_entities: true
  create_attack_patterns: true
  create_as_artifact: true
```

## Usage

### Workflow

1. **Connector starts** and connects to AssemblyLine
2. **Queries submissions** with score >= 1000 from the last N days
3. **For each malicious submission:**
   - Creates file artifact with hashes
   - Extracts malicious IOCs from tags
   - Creates indicators and observables
   - Extracts MITRE ATT&CK techniques
   - Creates Malware Analysis object
   - Links to existing artifacts
4. **Waits** for the configured interval
5. **Repeats**

### Viewing Results in OpenCTI

#### Malware Analysis Section

Navigate to **Observations** → **Artifacts** → Select an artifact → **Malware Analysis** tab

You'll see the AssemblyLine analysis report with:
- Analysis result (malicious/suspicious/benign)
- Link to AssemblyLine report
- Related objects (domains, IPs, URLs)

#### Indicators

Navigate to **Observations** → **Indicators**

Filter by label `assemblyline` to see all imported indicators.

#### Relationships

Each imported file artifact will have relationships to:
- Indicators (related-to)
- Malware families (related-to)
- Attack Patterns (uses)

## Objects Created

### STIX Domain Objects (SDOs)

| Object Type | Description |
|-------------|-------------|
| **Identity** | AssemblyLine organization identity |
| **Indicator** | Malicious domains, IPs, URLs |
| **Malware** | Detected malware families |
| **Attack Pattern** | MITRE ATT&CK techniques |
| **Malware Analysis** | Analysis report with results |

### STIX Cyber Observables (SCOs)

| Object Type | Description |
|-------------|-------------|
| **Artifact** | Analyzed file (binary) |
| **File** | Analyzed file (metadata) |
| **Domain-Name** | Malicious domains |
| **IPv4-Addr / IPv6-Addr** | Malicious IP addresses |
| **URL** | Malicious URLs |

### Relationships

| Relationship | From | To |
|--------------|------|-----|
| `related-to` | Artifact | Indicator |
| `related-to` | Artifact | Malware |
| `based-on` | Indicator | Observable |
| `uses` | Artifact | Attack Pattern |

## Troubleshooting

### Common Issues

#### Connection Failed to AssemblyLine

```
ERROR - Failed to initialize AssemblyLine client: ...
```

**Solution:**
- Verify `ASSEMBLYLINE_URL` is correct and accessible
- Check API credentials (`ASSEMBLYLINE_USER`, `ASSEMBLYLINE_APIKEY`)
- If using self-signed certificates, set `ASSEMBLYLINE_VERIFY_SSL=false`

#### No Submissions Found

```
INFO - Found 0 malicious submissions
```

**Solution:**
- Increase `ASSEMBLYLINE_LOOKBACK_DAYS`
- Verify AssemblyLine has submissions with score >= 1000
- Check AssemblyLine user has permission to view submissions

#### Malware Analysis Not Appearing

```
WARNING - No standard_id for file object, cannot create Malware Analysis
```

**Solution:**
- Ensure `ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS=true`
- Check OpenCTI version >= 6.0 (required for Malware Analysis SDO)

#### TLP Marking Errors

```
WARNING - Could not add TLP marking: ...
```

**Solution:**
- Verify TLP level is valid: `TLP:RED`, `TLP:AMBER`, `TLP:GREEN`, `TLP:WHITE`, `TLP:CLEAR`
- Ensure TLP markings are imported in OpenCTI (via OpenCTI Datasets connector)

### Logs

View connector logs:

```bash
# Docker
docker logs -f connector-assemblyline-import

# Docker Compose
docker-compose logs -f connector-assemblyline-import
```

Enable debug logging:

```yaml
- CONNECTOR_LOG_LEVEL=debug
```

### Health Check

Verify connector is registered in OpenCTI:

1. Navigate to **Data** → **Ingestion** → **Connectors**
2. Look for "AssemblyLine Import" connector
3. Check status is "Running" or "Waiting"

## API Reference

### AssemblyLine API Endpoints Used

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v4/user/whoami/` | GET | Verify authentication |
| `/api/v4/search/submission/` | GET | Search for submissions |
| `/api/v4/submission/full/{sid}/` | GET | Get submission details |
| `/api/v4/submission/summary/{sid}/` | GET | Get submission summary with tags |

### OpenCTI API Methods Used

- `identity.create()` / `identity.list()`
- `stix_cyber_observable.create()`
- `indicator.create()` / `indicator.list()`
- `malware.create()` / `malware.list()`
- `attack_pattern.create()` / `attack_pattern.list()`
- `stix_core_relationship.create()`
- `send_stix2_bundle()`

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/opencti-assemblyline-import.git
cd opencti-assemblyline-import

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Run linting
pylint src/
```

## Related Projects

- [OpenCTI](https://github.com/OpenCTI-Platform/opencti) - Open Cyber Threat Intelligence Platform
- [OpenCTI Connectors](https://github.com/OpenCTI-Platform/connectors) - Official OpenCTI connectors
- [AssemblyLine](https://github.com/CybercentreCanada/assemblyline) - Scalable malware analysis framework
- [S1EM](https://github.com/V1D1AN/S1EM) - Security Information and Event Management platform

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Canadian Centre for Cyber Security](https://cyber.gc.ca/) for AssemblyLine
- [Filigran](https://filigran.io/) for OpenCTI
- OpenCTI community for connector examples and documentation

---

**Made with ❤️ for the cybersecurity community**
