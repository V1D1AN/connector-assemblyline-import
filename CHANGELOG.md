# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-24

### Added

- Initial release of the OpenCTI AssemblyLine Import Connector
- **Malware Analysis Objects**: Creates STIX 2.1 Malware Analysis SDOs that appear in OpenCTI's dedicated "Malware Analysis" section
- **Indicators Creation**: Automatically creates indicators for malicious domains, IPs, and URLs
- **Observables Creation**: Creates corresponding observables with "based-on" relationships to indicators
- **MITRE ATT&CK Mapping**: Extracts and creates Attack Patterns from AssemblyLine's attack_matrix
- **Malware Families**: Identifies and creates Malware entities for detected families
- **Artifact Linking**: Links newly imported files with existing artifacts in OpenCTI
- **TLP Support**: Configurable TLP marking for all created objects (RED, AMBER, GREEN, WHITE, CLEAR)
- **AssemblyLine Attribution**: All objects are attributed to "AssemblyLine" identity
- **Configurable Features**: Enable/disable individual features via environment variables
- **Docker Support**: Dockerfile and docker-compose.yml for easy deployment
- **Comprehensive Documentation**: Full README with installation, configuration, and troubleshooting guides

### Features Configuration

- `ASSEMBLYLINE_CREATE_NETWORK_INDICATORS` - Create indicators for domains/IPs/URLs
- `ASSEMBLYLINE_CREATE_OBSERVABLES` - Create observables with based-on relationships
- `ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS` - Create Malware Analysis objects
- `ASSEMBLYLINE_CREATE_MALWARE_ENTITIES` - Create Malware family entities
- `ASSEMBLYLINE_CREATE_ATTACK_PATTERNS` - Create MITRE ATT&CK patterns
- `ASSEMBLYLINE_INCLUDE_SUSPICIOUS` - Include suspicious IOCs in addition to malicious

### Compatibility

- OpenCTI >= 6.0.0
- AssemblyLine >= 4.0
- Python >= 3.11

## [Unreleased]

### Planned

- Support for AssemblyLine submission filtering by classification
- Batch processing improvements for large imports
- Webhook support for real-time imports
- Support for custom indicator patterns
- Integration with AssemblyLine alerts/notifications
