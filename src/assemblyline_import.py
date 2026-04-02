#!/usr/bin/env python3
"""
OpenCTI AssemblyLine Import Connector - Enhanced Version
Imports malicious submissions from AssemblyLine into OpenCTI

Features:
- Creates Malware Analysis objects (like Hybrid Analysis)
- Creates both Indicators AND Observables with based-on relationships
- Extracts MITRE ATT&CK techniques
- Links to existing artifacts
- Full AssemblyLine attribution
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from assemblyline_client import get_client
from pycti import OpenCTIConnectorHelper, get_config_variable
import stix2


class AssemblyLineImportConnector:
    """Enhanced AssemblyLine Import Connector for OpenCTI"""

    def __init__(self):
        # Initialize the connector helper
        self.helper = OpenCTIConnectorHelper({})

        # AssemblyLine configuration from environment variables
        self.assemblyline_url = get_config_variable(
            "ASSEMBLYLINE_URL", ["assemblyline_import", "assemblyline_url"], {}
        )
        self.assemblyline_user = get_config_variable(
            "ASSEMBLYLINE_USER", ["assemblyline_import", "assemblyline_user"], {}
        )
        self.assemblyline_apikey = get_config_variable(
            "ASSEMBLYLINE_APIKEY", ["assemblyline_import", "assemblyline_apikey"], {}
        )
        self.assemblyline_verify_ssl = get_config_variable(
            "ASSEMBLYLINE_VERIFY_SSL",
            ["assemblyline_import", "assemblyline_verify_ssl"],
            {}, True, True
        )

        # File creation behavior
        self.create_as_artifact = get_config_variable(
            "ASSEMBLYLINE_CREATE_AS_ARTIFACT",
            ["assemblyline", "create_as_artifact"],
            {}, True, True
        )
        if isinstance(self.create_as_artifact, str):
            self.create_as_artifact = self.create_as_artifact.lower() == 'true'

        self.create_hash_observables = get_config_variable(
            "ASSEMBLYLINE_CREATE_HASH_OBSERVABLES",
            ["assemblyline", "create_hash_observables"],
            {}, True, True
        )
        if isinstance(self.create_hash_observables, str):
            self.create_hash_observables = self.create_hash_observables.lower() == 'true'

        # Import configuration
        self.import_interval = get_config_variable(
            "ASSEMBLYLINE_IMPORT_INTERVAL",
            ["assemblyline_import", "interval"],
            {}, 240, True
        )

        # Lookback configuration
        # LOOKBACK_HOURS takes priority over LOOKBACK_DAYS if set
        self.lookback_hours = get_config_variable(
            "ASSEMBLYLINE_LOOKBACK_HOURS",
            ["assemblyline_import", "lookback_hours"],
            {}, False, None
        )
        if self.lookback_hours is not None:
            try:
                self.lookback_hours = float(self.lookback_hours)
            except (ValueError, TypeError):
                self.lookback_hours = None

        self.lookback_days = get_config_variable(
            "ASSEMBLYLINE_LOOKBACK_DAYS",
            ["assemblyline_import", "lookback_days"],
            {}, 1, True
        )
        if isinstance(self.lookback_days, str):
            try:
                self.lookback_days = int(self.lookback_days)
            except ValueError:
                self.lookback_days = 1

        # TLP level configuration
        try:
            self.tlp_level = get_config_variable(
                "ASSEMBLYLINE_TLP_LEVEL",
                ["assemblyline_import", "tlp_level"],
                {}, False, "TLP:WHITE"
            )
            if not self.tlp_level:
                self.tlp_level = "TLP:WHITE"

            valid_tlp_levels = ["TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:WHITE", "TLP:CLEAR"]
            if str(self.tlp_level).upper() not in valid_tlp_levels:
                self.tlp_level = "TLP:WHITE"
            else:
                self.tlp_level = str(self.tlp_level).upper()
        except Exception as e:
            self.tlp_level = "TLP:WHITE"

        # Feature flags
        self.create_network_indicators = get_config_variable(
            "ASSEMBLYLINE_CREATE_NETWORK_INDICATORS",
            ["assemblyline", "create_network_indicators"],
            {}, True, True
        )
        if isinstance(self.create_network_indicators, str):
            self.create_network_indicators = self.create_network_indicators.lower() == 'true'

        # NEW: Create observables from indicators
        self.create_observables = get_config_variable(
            "ASSEMBLYLINE_CREATE_OBSERVABLES",
            ["assemblyline", "create_observables"],
            {}, True, True
        )
        if isinstance(self.create_observables, str):
            self.create_observables = self.create_observables.lower() == 'true'

        # NEW: Create Malware Analysis objects (like Hybrid Analysis)
        self.create_malware_analysis = get_config_variable(
            "ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS",
            ["assemblyline", "create_malware_analysis"],
            {}, True, True
        )
        if isinstance(self.create_malware_analysis, str):
            self.create_malware_analysis = self.create_malware_analysis.lower() == 'true'

        # Include suspicious IOCs
        self.assemblyline_include_suspicious = get_config_variable(
            "ASSEMBLYLINE_INCLUDE_SUSPICIOUS",
            ["assemblyline_import", "include_suspicious"],
            {}, False, True
        )
        if isinstance(self.assemblyline_include_suspicious, str):
            self.assemblyline_include_suspicious = self.assemblyline_include_suspicious.lower() == 'true'

        self.create_malware_entities = get_config_variable(
            "ASSEMBLYLINE_CREATE_MALWARE_ENTITIES",
            ["assemblyline", "create_malware_entities"],
            {}, True, True
        )
        if isinstance(self.create_malware_entities, str):
            self.create_malware_entities = self.create_malware_entities.lower() == 'true'

        self.create_attack_patterns = get_config_variable(
            "ASSEMBLYLINE_CREATE_ATTACK_PATTERNS",
            ["assemblyline", "create_attack_patterns"],
            {}, True, True
        )
        if isinstance(self.create_attack_patterns, str):
            self.create_attack_patterns = self.create_attack_patterns.lower() == 'true'

        # Create unclassified observables (domains/URLs/emails not tagged malicious)
        self.create_unclassified_observables = get_config_variable(
            "ASSEMBLYLINE_CREATE_UNCLASSIFIED_OBSERVABLES",
            ["assemblyline", "create_unclassified_observables"],
            {}, False, False
        )
        if isinstance(self.create_unclassified_observables, str):
            self.create_unclassified_observables = self.create_unclassified_observables.lower() in ('true', '1', 'yes')

        # Score assigned to unclassified observables (0-100)
        self.unclassified_score = int(get_config_variable(
            "ASSEMBLYLINE_UNCLASSIFIED_SCORE",
            ["assemblyline", "unclassified_score"],
            {}, False, 20
        ))

        # Initialize AssemblyLine client
        self.al_client = None
        self._init_assemblyline_client()

        # Cache for AssemblyLine identity
        self.assemblyline_identity_id = None
        self.assemblyline_identity_standard_id = None

    def _init_assemblyline_client(self):
        """Initialize AssemblyLine client with authentication"""
        try:
            self.helper.log_info("Initializing AssemblyLine client...")

            self.al_client = get_client(
                self.assemblyline_url,
                apikey=(self.assemblyline_user, self.assemblyline_apikey),
                verify=self.assemblyline_verify_ssl
            )

            # Test connection
            user_info = self.al_client.user.whoami()
            self.helper.log_info(f"Connected to AssemblyLine as user: {user_info['username']}")

        except Exception as e:
            self.helper.log_error(f"Failed to initialize AssemblyLine client: {str(e)}")
            raise

    def _get_tlp_marking(self) -> str:
        """Get the TLP marking ID for the configured TLP level"""
        tlp_mappings = {
            "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
        }
        return tlp_mappings.get(self.tlp_level, tlp_mappings["TLP:WHITE"])

    def _get_or_create_assemblyline_identity(self) -> Optional[str]:
        """Get or create AssemblyLine identity as the author"""
        if self.assemblyline_identity_id:
            return self.assemblyline_identity_id

        try:
            # Try to find existing AssemblyLine identity
            identities = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": ["AssemblyLine"]}],
                    "filterGroups": []
                }
            )

            if identities and len(identities) > 0:
                self.assemblyline_identity_id = identities[0]["id"]
                self.assemblyline_identity_standard_id = identities[0].get("standard_id")
                self.helper.log_info("Found existing AssemblyLine identity")
                return self.assemblyline_identity_id

            # Create new AssemblyLine identity
            self.helper.log_info("Creating new AssemblyLine identity")
            identity = self.helper.api.identity.create(
                type="Organization",
                name="AssemblyLine",
                description="AssemblyLine - Advanced Malware Analysis Platform by Canadian Centre for Cyber Security",
                x_opencti_aliases=["AL", "AssemblyLine Platform", "CCCS AssemblyLine"],
                contact_information="https://cybercentrecanada.github.io/assemblyline4_docs/",
                x_opencti_organization_type="cybersecurity-vendor"
            )

            if identity:
                self.assemblyline_identity_id = identity["id"]
                self.assemblyline_identity_standard_id = identity.get("standard_id")
                return self.assemblyline_identity_id

        except Exception as e:
            self.helper.log_error(f"Error getting/creating AssemblyLine identity: {str(e)}")

        return None

    def _score_to_result(self, score: int) -> str:
        """Convert AssemblyLine score to STIX malware-result-ov vocabulary"""
        if score >= 500:
            return "malicious"
        elif score >= 100:
            return "suspicious"
        elif score > 0:
            return "unknown"
        else:
            return "benign"

    def _create_file_object(self, submission: Dict) -> Optional[Dict]:
        """Create a file object (Artifact or StixFile) as the central hub"""
        try:
            sid = submission.get('sid', '')
            max_score = submission.get('max_score', 0)

            assemblyline_identity = self._get_or_create_assemblyline_identity()

            # Extract hashes from multiple possible locations
            sha256 = None
            sha1 = None
            md5 = None
            file_size = None
            file_type = None
            file_name = None

            # Method 1: From file_info
            file_info = submission.get('file_info', {})
            if file_info:
                sha256 = file_info.get('sha256')
                sha1 = file_info.get('sha1')
                md5 = file_info.get('md5')
                file_size = file_info.get('size')
                file_type = file_info.get('type')

            # Method 2: From files array
            if not sha256 and 'files' in submission:
                files = submission['files']
                if files and len(files) > 0:
                    first_file = files[0]
                    sha256 = first_file.get('sha256')
                    sha1 = first_file.get('sha1')
                    md5 = first_file.get('md5')
                    file_size = first_file.get('size')
                    file_name = first_file.get('name')

            # Method 3: From params
            if not sha256 and 'params' in submission:
                params = submission['params']
                sha256 = params.get('sha256')
                file_name = params.get('description', params.get('submitter', ''))

            if not sha256:
                self.helper.log_warning(f"No SHA-256 found for submission {sid}")
                return None

            # Create file object
            if self.create_as_artifact:
                artifact_data = {
                    "type": "artifact",
                    "x_opencti_description": f"File analyzed by AssemblyLine (Score: {max_score}/2000, SID: {sid}) - Source: AssemblyLine Platform"
                }

                if sha256:
                    artifact_data["hashes"] = {"SHA-256": sha256}
                    if sha1:
                        artifact_data["hashes"]["SHA-1"] = sha1
                    if md5:
                        artifact_data["hashes"]["MD5"] = md5

                if file_type:
                    artifact_data["mime_type"] = file_type

                try:
                    artifact_data["objectMarking"] = [self._get_tlp_marking()]
                except Exception:
                    pass

                file_object = self.helper.api.stix_cyber_observable.create(
                    observableData=artifact_data,
                    createdBy=assemblyline_identity
                )
            else:
                file_data = {
                    "type": "file",
                    "hashes": {"SHA-256": sha256},
                    "x_opencti_description": f"File analyzed by AssemblyLine (Score: {max_score}/2000, SID: {sid}) - Source: AssemblyLine Platform"
                }

                if sha1:
                    file_data["hashes"]["SHA-1"] = sha1
                if md5:
                    file_data["hashes"]["MD5"] = md5
                if file_size:
                    file_data["size"] = file_size
                if file_type:
                    file_data["mime_type"] = file_type
                if file_name:
                    file_data["name"] = file_name

                try:
                    file_data["objectMarking"] = [self._get_tlp_marking()]
                except Exception:
                    pass

                file_object = self.helper.api.stix_cyber_observable.create(
                    observableData=file_data,
                    createdBy=assemblyline_identity
                )

            if file_object:
                self.helper.log_info(f"Created file object: {sha256[:16]}... -> {file_object['id']}")
                return {
                    "id": file_object["id"],
                    "standard_id": file_object.get("standard_id"),
                    "type": "artifact" if self.create_as_artifact else "file",
                    "sha256": sha256,
                    "sha1": sha1,
                    "md5": md5,
                    "file_size": file_size,
                    "file_type": file_type,
                    "file_name": file_name
                }

            return None

        except Exception as e:
            self.helper.log_error(f"Error creating file object: {str(e)}")
            return None

    def _extract_malicious_iocs(self, tags: Dict) -> Dict:
        """Extract malicious IOCs from AssemblyLine tags"""
        malicious_iocs = {
            'domains': [],
            'ips': [],
            'urls': [],
            'families': []
        }

        if not tags:
            return malicious_iocs

        classification_types = ["malicious"]
        if self.assemblyline_include_suspicious:
            classification_types.append("suspicious")

        for main_category, category_data in tags.items():
            if not isinstance(category_data, dict):
                continue

            for tag_type, tag_list in category_data.items():
                if not isinstance(tag_list, list):
                    continue

                for tag_entry in tag_list:
                    if not isinstance(tag_entry, list) or len(tag_entry) < 2:
                        continue

                    value = tag_entry[0]
                    classification = tag_entry[1]

                    should_include = classification in classification_types

                    if not should_include:
                        continue

                    if "domain" in tag_type.lower():
                        if value not in malicious_iocs['domains']:
                            malicious_iocs['domains'].append(value)

                    elif "ip" in tag_type.lower():
                        if value not in malicious_iocs['ips']:
                            malicious_iocs['ips'].append(value)

                    elif "uri" in tag_type.lower() or "url" in tag_type.lower():
                        if value not in malicious_iocs['urls']:
                            malicious_iocs['urls'].append(value)

            # Handle attribution families
            if main_category == "attribution":
                if "attribution.family" in category_data:
                    family_list = category_data["attribution.family"]
                    for family_entry in family_list:
                        if isinstance(family_entry, list) and len(family_entry) >= 1:
                            family_name = family_entry[0]
                            if family_name not in malicious_iocs['families']:
                                malicious_iocs['families'].append(family_name)

        self.helper.log_info(
            f"Extracted IOCs - Domains: {len(malicious_iocs['domains'])}, "
            f"IPs: {len(malicious_iocs['ips'])}, URLs: {len(malicious_iocs['urls'])}, "
            f"Families: {len(malicious_iocs['families'])}"
        )

        return malicious_iocs

    def _extract_unclassified_iocs(self, tags: Dict, malicious_iocs: Dict) -> Dict:
        """
        Extract IOCs not classified as malicious/suspicious by AssemblyLine.
        Domains, URLs and emails only (no IPs to avoid version string false positives).
        Filtering of legitimate domains is delegated to AssemblyLine safelists and OpenCTI exclusion lists.
        """
        unclassified_iocs = {
            'domains': [],
            'urls': [],
            'emails': []
        }

        if not tags:
            return unclassified_iocs

        for main_category, category_data in tags.items():
            if not isinstance(category_data, dict):
                continue

            for tag_type, tag_list in category_data.items():
                if not isinstance(tag_list, list):
                    continue

                for tag_entry in tag_list:
                    if not isinstance(tag_entry, list) or len(tag_entry) < 2:
                        continue

                    value = tag_entry[0]
                    classification = tag_entry[1]

                    if classification in ["malicious", "suspicious"]:
                        continue

                    is_domain = "domain" in tag_type.lower()
                    is_url = "uri" in tag_type.lower() or "url" in tag_type.lower()
                    is_email = "email" in tag_type.lower()

                    if not is_domain and not is_url and not is_email:
                        continue

                    if is_domain and value in malicious_iocs.get('domains', []):
                        continue
                    if is_url and value in malicious_iocs.get('urls', []):
                        continue

                    if is_domain and value not in unclassified_iocs['domains']:
                        unclassified_iocs['domains'].append(value)
                    elif is_url and value not in unclassified_iocs['urls']:
                        unclassified_iocs['urls'].append(value)
                    elif is_email and value not in unclassified_iocs['emails']:
                        unclassified_iocs['emails'].append(value)

        self.helper.log_info(
            f"Extracted unclassified IOCs - Domains: {len(unclassified_iocs['domains'])}, "
            f"URLs: {len(unclassified_iocs['urls'])}, Emails: {len(unclassified_iocs['emails'])}"
        )

        return unclassified_iocs

    def _has_verdict_label(self, observable_id: str) -> bool:
        """
        Check if an observable already has a verdict label (legitimate or malicious).
        If so, we should NOT overwrite it with 'assemblyline-unverified'.
        """
        try:
            observable = self.helper.api.stix_cyber_observable.read(id=observable_id)
            if observable and "objectLabel" in observable:
                existing_labels = [
                    lbl["value"].lower()
                    for lbl in observable["objectLabel"]
                    if isinstance(lbl, dict) and "value" in lbl
                ]
                verdict_labels = {"legitimate", "malicious"}
                if verdict_labels & set(existing_labels):
                    self.helper.log_info(
                        f"Observable {observable_id} already has verdict label "
                        f"({', '.join(verdict_labels & set(existing_labels))}), "
                        f"skipping assemblyline-unverified"
                    )
                    return True
        except Exception as e:
            self.helper.log_warning(f"Could not check labels for {observable_id}: {str(e)}")
        return False

    def _create_unclassified_observables(self, file_id: str, unclassified_iocs: Dict,
                                          assemblyline_identity: str) -> Dict:
        """
        Create simple observables in OpenCTI for unclassified IOCs.
        No indicators, no malicious label, low confidence score.
        Links to the StixFile/Artifact with 'related-to' relationship.
        """
        created_counts = {
            'unclassified_domains': 0,
            'unclassified_urls': 0,
            'unclassified_emails': 0
        }

        for domain in unclassified_iocs['domains'][:30]:
            try:
                obs = self.helper.api.stix_cyber_observable.create(
                    observableData={"type": "domain-name", "value": domain},
                    x_opencti_score=self.unclassified_score,
                    createdBy=assemblyline_identity
                )
                created_counts['unclassified_domains'] += 1

                if not self._has_verdict_label(obs["id"]):
                    self.helper.api.stix_cyber_observable.add_label(
                        id=obs["id"], label_name="assemblyline-unverified"
                    )
                self.helper.api.stix_core_relationship.create(
                    fromId=file_id, toId=obs["id"],
                    relationship_type="related-to",
                    description="Domain observed during AssemblyLine analysis (not yet verified as malicious)",
                    createdBy=assemblyline_identity
                )
            except Exception as e:
                self.helper.log_warning(f"Could not create unclassified domain {domain}: {str(e)}")

        for url in unclassified_iocs['urls'][:30]:
            try:
                obs = self.helper.api.stix_cyber_observable.create(
                    observableData={"type": "url", "value": url},
                    x_opencti_score=self.unclassified_score,
                    createdBy=assemblyline_identity
                )
                created_counts['unclassified_urls'] += 1

                if not self._has_verdict_label(obs["id"]):
                    self.helper.api.stix_cyber_observable.add_label(
                        id=obs["id"], label_name="assemblyline-unverified"
                    )
                self.helper.api.stix_core_relationship.create(
                    fromId=file_id, toId=obs["id"],
                    relationship_type="related-to",
                    description="URL observed during AssemblyLine analysis (not yet verified as malicious)",
                    createdBy=assemblyline_identity
                )
            except Exception as e:
                self.helper.log_warning(f"Could not create unclassified URL {url}: {str(e)}")

        for email in unclassified_iocs.get('emails', [])[:30]:
            try:
                obs = self.helper.api.stix_cyber_observable.create(
                    observableData={"type": "email-addr", "value": email},
                    x_opencti_score=self.unclassified_score,
                    createdBy=assemblyline_identity
                )
                created_counts['unclassified_emails'] += 1

                if not self._has_verdict_label(obs["id"]):
                    self.helper.api.stix_cyber_observable.add_label(
                        id=obs["id"], label_name="assemblyline-unverified"
                    )
                self.helper.api.stix_core_relationship.create(
                    fromId=file_id, toId=obs["id"],
                    relationship_type="related-to",
                    description="Email observed during AssemblyLine analysis (not yet verified as malicious)",
                    createdBy=assemblyline_identity
                )
            except Exception as e:
                self.helper.log_warning(f"Could not create unclassified email {email}: {str(e)}")

        total = sum(created_counts.values())
        self.helper.log_info(f"Created {total} unclassified observables (domains: {created_counts['unclassified_domains']}, URLs: {created_counts['unclassified_urls']}, emails: {created_counts['unclassified_emails']})")

        return created_counts

    def _extract_attack_techniques(self, attack_matrix: Dict) -> List[Dict]:
        """Extract MITRE ATT&CK techniques from AssemblyLine attack_matrix"""
        techniques = []

        if not attack_matrix:
            return techniques

        for category, category_data in attack_matrix.items():
            if not isinstance(category_data, list):
                continue

            for technique_entry in category_data:
                if isinstance(technique_entry, list) and len(technique_entry) >= 2:
                    technique_id = technique_entry[0]
                    technique_name = technique_entry[1] if len(technique_entry) > 1 else technique_id

                    if technique_id.startswith("T") and technique_id not in [t['id'] for t in techniques]:
                        techniques.append({
                            'id': technique_id,
                            'name': technique_name,
                            'tactic': category
                        })

        self.helper.log_info(f"Extracted {len(techniques)} ATT&CK techniques")
        return techniques

    def _create_observable_for_indicator(self, indicator_type: str, value: str, assemblyline_identity: str) -> Optional[str]:
        """Create an observable and return its ID"""
        try:
            observable_data = {}

            if indicator_type == "domain":
                observable_data = {
                    "type": "domain-name",
                    "value": value
                }
            elif indicator_type == "ip":
                # Detect IPv4 vs IPv6
                if ":" in value:
                    observable_data = {
                        "type": "ipv6-addr",
                        "value": value
                    }
                else:
                    observable_data = {
                        "type": "ipv4-addr",
                        "value": value
                    }
            elif indicator_type == "url":
                observable_data = {
                    "type": "url",
                    "value": value
                }

            if not observable_data:
                return None

            # Add labels
            observable = self.helper.api.stix_cyber_observable.create(
                observableData=observable_data,
                createdBy=assemblyline_identity
            )

            if observable:
                # Add malicious label
                try:
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable["id"],
                        label_name="malicious"
                    )
                except Exception:
                    pass

                return observable["id"]

            return None

        except Exception as e:
            self.helper.log_warning(f"Could not create observable for {indicator_type} {value}: {str(e)}")
            return None

    def _create_indicators_with_observables(self, file_id: str, malicious_iocs: Dict, submission: Dict) -> Dict:
        """Create indicators AND their corresponding observables with based-on relationships"""
        stats = {
            'indicators_created': 0,
            'observables_created': 0,
            'relationships_created': 0
        }

        max_score = submission.get('max_score', 0)
        sid = submission.get('sid', '')
        assemblyline_identity = self._get_or_create_assemblyline_identity()

        # Process domains
        for domain in malicious_iocs['domains'][:20]:
            try:
                indicator_data = {
                    "name": domain,
                    "description": f"Malicious domain identified by AssemblyLine (score: {max_score}) - Source: AssemblyLine Platform",
                    "pattern": f"[domain-name:value = '{domain}']",
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": "Domain-Name",
                    "valid_from": self.helper.api.stix2.format_date(),
                    "labels": ["malicious", "assemblyline"],
                    "x_opencti_score": 85,
                    "external_references": [{
                        "source_name": "AssemblyLine",
                        "description": "Detected in malware analysis",
                        "url": f"{self.assemblyline_url}/submission/{sid}"
                    }]
                }

                if assemblyline_identity:
                    indicator_data["createdBy"] = assemblyline_identity

                try:
                    indicator_data["objectMarking"] = [self._get_tlp_marking()]
                except Exception:
                    pass

                indicator = self.helper.api.indicator.create(**indicator_data)

                if indicator:
                    stats['indicators_created'] += 1

                    # Create relationship file -> indicator
                    try:
                        self.helper.api.stix_core_relationship.create(
                            fromId=file_id,
                            toId=indicator["id"],
                            relationship_type="related-to",
                            description="Domain contacted during malware analysis",
                            createdBy=assemblyline_identity
                        )
                        stats['relationships_created'] += 1
                    except Exception:
                        pass

                    # Create observable if enabled
                    if self.create_observables:
                        observable_id = self._create_observable_for_indicator("domain", domain, assemblyline_identity)
                        if observable_id:
                            stats['observables_created'] += 1

                            # Create based-on relationship
                            try:
                                self.helper.api.stix_core_relationship.create(
                                    fromId=indicator["id"],
                                    toId=observable_id,
                                    relationship_type="based-on",
                                    description="Indicator based on this observable",
                                    createdBy=assemblyline_identity
                                )
                                stats['relationships_created'] += 1
                            except Exception:
                                pass

            except Exception as e:
                self.helper.log_warning(f"Could not create domain indicator {domain}: {str(e)}")

        # Process IPs
        for ip in malicious_iocs['ips'][:20]:
            try:
                # Skip localhost IPs
                if ip in ['127.0.0.1', '::1', '0.0.0.0']:
                    continue

                ip_type = "IPv6-Addr" if ":" in ip else "IPv4-Addr"
                pattern_type = "ipv6-addr" if ":" in ip else "ipv4-addr"

                indicator_data = {
                    "name": ip,
                    "description": f"Malicious IP identified by AssemblyLine (score: {max_score}) - Source: AssemblyLine Platform",
                    "pattern": f"[{pattern_type}:value = '{ip}']",
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": ip_type,
                    "valid_from": self.helper.api.stix2.format_date(),
                    "labels": ["malicious", "assemblyline"],
                    "x_opencti_score": 85,
                    "external_references": [{
                        "source_name": "AssemblyLine",
                        "description": "Detected in malware analysis",
                        "url": f"{self.assemblyline_url}/submission/{sid}"
                    }]
                }

                if assemblyline_identity:
                    indicator_data["createdBy"] = assemblyline_identity

                try:
                    indicator_data["objectMarking"] = [self._get_tlp_marking()]
                except Exception:
                    pass

                indicator = self.helper.api.indicator.create(**indicator_data)

                if indicator:
                    stats['indicators_created'] += 1

                    try:
                        self.helper.api.stix_core_relationship.create(
                            fromId=file_id,
                            toId=indicator["id"],
                            relationship_type="related-to",
                            description="IP contacted during malware analysis",
                            createdBy=assemblyline_identity
                        )
                        stats['relationships_created'] += 1
                    except Exception:
                        pass

                    if self.create_observables:
                        observable_id = self._create_observable_for_indicator("ip", ip, assemblyline_identity)
                        if observable_id:
                            stats['observables_created'] += 1

                            try:
                                self.helper.api.stix_core_relationship.create(
                                    fromId=indicator["id"],
                                    toId=observable_id,
                                    relationship_type="based-on",
                                    description="Indicator based on this observable",
                                    createdBy=assemblyline_identity
                                )
                                stats['relationships_created'] += 1
                            except Exception:
                                pass

            except Exception as e:
                self.helper.log_warning(f"Could not create IP indicator {ip}: {str(e)}")

        # Process URLs
        for url in malicious_iocs['urls'][:20]:
            try:
                indicator_data = {
                    "name": url[:100],
                    "description": f"Malicious URL identified by AssemblyLine (score: {max_score}) - Source: AssemblyLine Platform",
                    "pattern": f"[url:value = '{url}']",
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": "Url",
                    "valid_from": self.helper.api.stix2.format_date(),
                    "labels": ["malicious", "assemblyline"],
                    "x_opencti_score": 80,
                    "external_references": [{
                        "source_name": "AssemblyLine",
                        "description": "Detected in malware analysis",
                        "url": f"{self.assemblyline_url}/submission/{sid}"
                    }]
                }

                if assemblyline_identity:
                    indicator_data["createdBy"] = assemblyline_identity

                try:
                    indicator_data["objectMarking"] = [self._get_tlp_marking()]
                except Exception:
                    pass

                indicator = self.helper.api.indicator.create(**indicator_data)

                if indicator:
                    stats['indicators_created'] += 1

                    try:
                        self.helper.api.stix_core_relationship.create(
                            fromId=file_id,
                            toId=indicator["id"],
                            relationship_type="related-to",
                            description="URL contacted during malware analysis",
                            createdBy=assemblyline_identity
                        )
                        stats['relationships_created'] += 1
                    except Exception:
                        pass

                    if self.create_observables:
                        observable_id = self._create_observable_for_indicator("url", url, assemblyline_identity)
                        if observable_id:
                            stats['observables_created'] += 1

                            try:
                                self.helper.api.stix_core_relationship.create(
                                    fromId=indicator["id"],
                                    toId=observable_id,
                                    relationship_type="based-on",
                                    description="Indicator based on this observable",
                                    createdBy=assemblyline_identity
                                )
                                stats['relationships_created'] += 1
                            except Exception:
                                pass

            except Exception as e:
                self.helper.log_warning(f"Could not create URL indicator {url[:50]}: {str(e)}")

        return stats

    def _create_malware_analysis_object(self, file_object: Dict, submission: Dict, malicious_iocs: Dict) -> Optional[str]:
        """
        Create a Malware Analysis SDO that appears in the 'Malware Analysis' section.
        Uses STIX bundle approach like Hybrid Analysis connector.
        """
        if not self.create_malware_analysis:
            return None

        try:
            sid = submission.get('sid', '')
            max_score = submission.get('max_score', 0)
            file_info = submission.get('file_info', {})
            times = submission.get('times', {})

            # Get file details
            sha256 = file_object.get('sha256', 'unknown')
            file_type = file_object.get('file_type', 'unknown')
            sample_ref = file_object.get('standard_id')

            if not sample_ref:
                self.helper.log_warning("No standard_id for file object, cannot create Malware Analysis")
                return None

            # Determine result
            result_value = self._score_to_result(max_score)

            # Check for malicious IOCs
            has_malicious = (
                len(malicious_iocs['domains']) > 0 or
                len(malicious_iocs['ips']) > 0 or
                len(malicious_iocs['urls']) > 0 or
                len(malicious_iocs['families']) > 0
            )
            if has_malicious and result_value not in ["malicious", "suspicious"]:
                result_value = "malicious"

            # Get timestamps
            now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
            analysis_started = now
            analysis_ended = now

            if times:
                if times.get("submitted"):
                    try:
                        ts = times["submitted"]
                        if isinstance(ts, str):
                            if "." not in ts:
                                ts = ts.replace("Z", ".000Z")
                            else:
                                # Truncate nanoseconds to microseconds (6 digits max)
                                # AL may return 9-digit precision: 2026-03-25T20:33:29.646056452Z
                                # Python/stix2 only supports 6 digits: 2026-03-25T20:33:29.646056Z
                                parts = ts.split(".")
                                if len(parts) == 2:
                                    frac = parts[1].rstrip("Z")
                                    if len(frac) > 6:
                                        frac = frac[:6]
                                    ts = f"{parts[0]}.{frac}Z"
                            analysis_started = ts
                    except Exception:
                        pass
                if times.get("completed"):
                    try:
                        ts = times["completed"]
                        if isinstance(ts, str):
                            if "." not in ts:
                                ts = ts.replace("Z", ".000Z")
                            else:
                                # Truncate nanoseconds to microseconds (6 digits max)
                                parts = ts.split(".")
                                if len(parts) == 2:
                                    frac = parts[1].rstrip("Z")
                                    if len(frac) > 6:
                                        frac = frac[:6]
                                    ts = f"{parts[0]}.{frac}Z"
                            analysis_ended = ts
                    except Exception:
                        pass

            # Generate unique ID for the malware analysis
            malware_analysis_id = f"malware-analysis--{str(uuid.uuid4())}"

            # Build list of related SCO refs (observables found during analysis)
            analysis_sco_refs = [sample_ref]

            # Create STIX observables for IOCs and add to sco_refs
            stix_objects = []

            # Add domain observables
            for domain in malicious_iocs['domains'][:10]:
                try:
                    domain_id = f"domain-name--{str(uuid.uuid5(uuid.NAMESPACE_URL, domain))}"
                    domain_obj = stix2.DomainName(
                        id=domain_id,
                        value=domain
                    )
                    stix_objects.append(domain_obj)
                    analysis_sco_refs.append(domain_id)
                except Exception:
                    pass

            # Add IP observables
            for ip in malicious_iocs['ips'][:10]:
                if ip in ['127.0.0.1', '::1', '0.0.0.0']:
                    continue
                try:
                    if ":" in ip:
                        ip_id = f"ipv6-addr--{str(uuid.uuid5(uuid.NAMESPACE_URL, ip))}"
                        ip_obj = stix2.IPv6Address(id=ip_id, value=ip)
                    else:
                        ip_id = f"ipv4-addr--{str(uuid.uuid5(uuid.NAMESPACE_URL, ip))}"
                        ip_obj = stix2.IPv4Address(id=ip_id, value=ip)
                    stix_objects.append(ip_obj)
                    analysis_sco_refs.append(ip_id)
                except Exception:
                    pass

            # Add URL observables
            for url in malicious_iocs['urls'][:10]:
                try:
                    url_id = f"url--{str(uuid.uuid5(uuid.NAMESPACE_URL, url))}"
                    url_obj = stix2.URL(id=url_id, value=url)
                    stix_objects.append(url_obj)
                    analysis_sco_refs.append(url_id)
                except Exception:
                    pass

            # Build external reference
            external_reference = stix2.ExternalReference(
                source_name="AssemblyLine",
                url=f"{self.assemblyline_url}/submission/{sid}",
                description=f"AssemblyLine analysis report (Score: {max_score}/2000)"
            )

            # Create Malware Analysis object
            malware_analysis_props = {
                "id": malware_analysis_id,
                "product": "AssemblyLine",
                "result": result_value,
                "analysis_sco_refs": analysis_sco_refs,
                "submitted": analysis_started,
                "analysis_started": analysis_started,
                "analysis_ended": analysis_ended,
                "external_references": [external_reference]
            }

            # Add optional fields
            if file_type and file_type != "unknown":
                malware_analysis_props["sample_mime_types"] = [file_type]

            # Add created_by_ref
            if self.assemblyline_identity_standard_id:
                malware_analysis_props["created_by_ref"] = self.assemblyline_identity_standard_id

            malware_analysis = stix2.MalwareAnalysis(**malware_analysis_props)
            stix_objects.append(malware_analysis)

            # Create and send bundle
            bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)
            serialized_bundle = bundle.serialize()

            self.helper.log_info(f"Sending Malware Analysis bundle with {len(stix_objects)} objects...")
            self.helper.send_stix2_bundle(serialized_bundle)

            self.helper.log_info(f"Created Malware Analysis: {malware_analysis_id} (result: {result_value})")
            return malware_analysis_id

        except Exception as e:
            self.helper.log_error(f"Error creating Malware Analysis: {str(e)}")
            import traceback
            self.helper.log_error(f"Traceback: {traceback.format_exc()}")
            return None

    def _create_malware_entities(self, file_id: str, malicious_iocs: Dict, submission: Dict) -> int:
        """Create malware entities for detected families"""
        created_count = 0
        max_score = submission.get('max_score', 0)
        sid = submission.get('sid', '')
        assemblyline_identity = self._get_or_create_assemblyline_identity()

        for family in malicious_iocs['families'][:10]:
            try:
                malware_data = {
                    "name": family,
                    "description": f"Malware family '{family}' identified by AssemblyLine (score: {max_score}) - Source: AssemblyLine Platform",
                    "labels": ["trojan"],
                    "is_family": True,
                    "external_references": [{
                        "source_name": "AssemblyLine",
                        "description": "Detected in malware analysis",
                        "url": f"{self.assemblyline_url}/submission/{sid}"
                    }]
                }

                if assemblyline_identity:
                    malware_data["createdBy"] = assemblyline_identity

                try:
                    malware_data["objectMarking"] = [self._get_tlp_marking()]
                except Exception:
                    pass

                # Check if exists
                existing = None
                try:
                    results = self.helper.api.malware.list(
                        filters={
                            "mode": "and",
                            "filters": [{"key": "name", "values": [family]}],
                            "filterGroups": []
                        },
                        first=1
                    )
                    if results:
                        existing = results[0]
                except Exception:
                    pass

                if not existing:
                    malware = self.helper.api.malware.create(**malware_data)
                    if malware:
                        malware_id = malware["id"]
                        created_count += 1
                else:
                    malware_id = existing["id"]

                # Create relationship
                try:
                    self.helper.api.stix_core_relationship.create(
                        fromId=file_id,
                        toId=malware_id,
                        relationship_type="related-to",
                        description=f"File identified as {family} by AssemblyLine",
                        createdBy=assemblyline_identity
                    )
                except Exception:
                    pass

            except Exception as e:
                self.helper.log_warning(f"Could not create malware family {family}: {str(e)}")

        return created_count

    def _create_attack_patterns(self, file_id: str, techniques: List[Dict], submission: Dict) -> int:
        """Create ATT&CK patterns and link to file"""
        if not self.create_attack_patterns or not techniques:
            return 0

        created_count = 0
        sid = submission.get('sid', '')
        assemblyline_identity = self._get_or_create_assemblyline_identity()

        for technique in techniques[:20]:
            try:
                technique_id = technique['id']
                technique_name = technique.get('name', technique_id)
                tactic = technique.get('tactic', 'unknown')

                # Search for existing ATT&CK pattern
                existing = None
                try:
                    results = self.helper.api.attack_pattern.list(
                        filters={
                            "mode": "and",
                            "filters": [{"key": "x_mitre_id", "values": [technique_id]}],
                            "filterGroups": []
                        },
                        first=1
                    )
                    if results:
                        existing = results[0]
                except Exception:
                    pass

                if existing:
                    attack_pattern_id = existing["id"]
                else:
                    # Create new attack pattern
                    attack_pattern = self.helper.api.attack_pattern.create(
                        name=f"{technique_id} - {technique_name}",
                        description=f"MITRE ATT&CK technique {technique_id} observed by AssemblyLine - Source: AssemblyLine Platform",
                        x_mitre_id=technique_id,
                        kill_chain_phases=[{
                            "kill_chain_name": "mitre-attack",
                            "phase_name": tactic.lower().replace(" ", "-")
                        }],
                        createdBy=assemblyline_identity,
                        external_references=[{
                            "source_name": "mitre-attack",
                            "url": f"https://attack.mitre.org/techniques/{technique_id}/",
                            "external_id": technique_id
                        }]
                    )

                    if attack_pattern:
                        attack_pattern_id = attack_pattern["id"]
                        created_count += 1
                    else:
                        continue

                # Create "uses" relationship
                try:
                    self.helper.api.stix_core_relationship.create(
                        fromId=file_id,
                        toId=attack_pattern_id,
                        relationship_type="uses",
                        description=f"File uses technique {technique_id} as observed by AssemblyLine",
                        createdBy=assemblyline_identity
                    )
                except Exception:
                    pass

            except Exception as e:
                self.helper.log_warning(f"Could not create ATT&CK pattern {technique.get('id')}: {str(e)}")

        return created_count

    def _link_existing_artifacts(self, file_object: Dict, submission: Dict) -> int:
        """Find and link existing artifacts in OpenCTI"""
        linked_count = 0

        try:
            sha256 = file_object.get("sha256")
            sha1 = file_object.get("sha1")
            md5 = file_object.get("md5")
            file_id = file_object.get("id")
            sid = submission.get('sid', '')

            assemblyline_identity = self._get_or_create_assemblyline_identity()

            hash_searches = []
            if sha256:
                hash_searches.append(("SHA-256", sha256))
            if sha1:
                hash_searches.append(("SHA-1", sha1))
            if md5:
                hash_searches.append(("MD5", md5))

            existing_artifacts = set()

            for hash_type, hash_value in hash_searches:
                try:
                    results = self.helper.api.stix_cyber_observable.list(
                        filters={
                            "mode": "and",
                            "filters": [{"key": f"hashes.{hash_type}", "values": [hash_value]}],
                            "filterGroups": []
                        },
                        first=10
                    )

                    if results:
                        for artifact in results:
                            if artifact["id"] != file_id:
                                existing_artifacts.add(artifact["id"])

                except Exception:
                    pass

            for artifact_id in existing_artifacts:
                try:
                    self.helper.api.stix_core_relationship.create(
                        fromId=file_id,
                        toId=artifact_id,
                        relationship_type="related-to",
                        description=f"Same file analyzed in AssemblyLine (SID: {sid})",
                        createdBy=assemblyline_identity
                    )
                    linked_count += 1
                except Exception:
                    pass

            return linked_count

        except Exception as e:
            self.helper.log_error(f"Error linking artifacts: {str(e)}")
            return 0

    def _get_submission_details(self, sid: str) -> Optional[Dict]:
        """Get detailed submission information"""
        try:
            try:
                submission_summary = self.al_client.submission.summary(sid)
                try:
                    basic_submission = self.al_client.submission.full(sid)
                    combined = basic_submission.copy()
                    if 'tags' in submission_summary:
                        combined['tags'] = submission_summary['tags']
                    if 'attack_matrix' in submission_summary:
                        combined['attack_matrix'] = submission_summary['attack_matrix']
                    return combined
                except Exception:
                    return submission_summary
            except Exception:
                return self.al_client.submission.full(sid)
        except Exception as e:
            self.helper.log_error(f"Could not get details for {sid}: {str(e)}")
            return None

    def _process_submission(self, submission: Dict) -> Dict:
        """Process a single submission"""
        try:
            sid = submission.get('sid', '')
            max_score = submission.get('max_score', 0)

            # Get details
            detailed = self._get_submission_details(sid)
            if not detailed:
                return {"processed": False, "reason": "no_details"}

            # Extract IOCs
            tags = detailed.get('tags', {})
            malicious_iocs = self._extract_malicious_iocs(tags)
            total_iocs = len(malicious_iocs['domains']) + len(malicious_iocs['ips']) + len(malicious_iocs['urls'])

            # Extract ATT&CK techniques
            attack_matrix = detailed.get('attack_matrix', {})
            attack_techniques = self._extract_attack_techniques(attack_matrix)

            # Check thresholds
            has_malicious = total_iocs > 0
            meets_threshold = max_score >= 1000

            if not (has_malicious or meets_threshold):
                return {"processed": False, "reason": "below_threshold"}

            # Create file object
            file_object = self._create_file_object(detailed)
            if not file_object:
                return {"processed": False, "reason": "file_creation_failed"}

            file_id = file_object["id"]

            # Ensure we have identity
            self._get_or_create_assemblyline_identity()

            # Create indicators with observables
            indicator_stats = {'indicators_created': 0, 'observables_created': 0, 'relationships_created': 0}
            if self.create_network_indicators and total_iocs > 0:
                indicator_stats = self._create_indicators_with_observables(file_id, malicious_iocs, detailed)

            # Create malware entities
            created_malware = 0
            if self.create_malware_entities and malicious_iocs['families']:
                created_malware = self._create_malware_entities(file_id, malicious_iocs, detailed)

            # Create ATT&CK patterns
            created_attack = 0
            if attack_techniques:
                created_attack = self._create_attack_patterns(file_id, attack_techniques, detailed)

            # Create Malware Analysis object
            malware_analysis_id = None
            if self.create_malware_analysis:
                malware_analysis_id = self._create_malware_analysis_object(file_object, detailed, malicious_iocs)

            # Link existing artifacts
            linked = self._link_existing_artifacts(file_object, detailed)

            # Create unclassified observables if enabled
            unclassified_stats = {'unclassified_domains': 0, 'unclassified_urls': 0, 'unclassified_emails': 0}
            if self.create_unclassified_observables:
                unclassified_iocs = self._extract_unclassified_iocs(tags, malicious_iocs)
                if unclassified_iocs['domains'] or unclassified_iocs['urls'] or unclassified_iocs.get('emails'):
                    unclassified_stats = self._create_unclassified_observables(
                        file_id, unclassified_iocs, self.assemblyline_identity_id
                    )

            total_unclassified = sum(unclassified_stats.values())

            self.helper.log_info(
                f"Submission {sid} processed: "
                f"indicators={indicator_stats['indicators_created']}, "
                f"observables={indicator_stats['observables_created']}, "
                f"malware={created_malware}, attack={created_attack}, "
                f"unclassified={total_unclassified}, linked={linked}"
            )

            return {
                "processed": True,
                "sid": sid,
                "score": max_score,
                "file_id": file_id,
                "indicators_created": indicator_stats['indicators_created'],
                "observables_created": indicator_stats['observables_created'],
                "malware_created": created_malware,
                "attack_patterns_created": created_attack,
                "unclassified_created": total_unclassified,
                "malware_analysis": malware_analysis_id is not None,
                "linked_artifacts": linked
            }

        except Exception as e:
            self.helper.log_error(f"Error processing submission: {str(e)}")
            import traceback
            self.helper.log_error(traceback.format_exc())
            return {"processed": False, "reason": f"error: {str(e)}"}

    def _run_import(self):
        """Main import process"""
        try:
            self.helper.log_info("Starting AssemblyLine Enhanced Import...")

            end_time = datetime.now(timezone.utc)
            if self.lookback_hours is not None:
                start_time = end_time - timedelta(hours=self.lookback_hours)
                self.helper.log_info(f"Searching submissions from last {self.lookback_hours} hour(s)")
            else:
                start_time = end_time - timedelta(days=self.lookback_days)
                self.helper.log_info(f"Searching submissions from last {self.lookback_days} day(s)")

            self.helper.log_info(f"Searching submissions from {start_time} to {end_time}")

            query = f"max_score:[1000 TO *] AND times.submitted:[{start_time.strftime('%Y-%m-%dT%H:%M:%S')}Z TO {end_time.strftime('%Y-%m-%dT%H:%M:%S')}Z]"

            results = self.al_client.search.submission(query=query, rows=50)
            submissions = results.get('items', [])

            self.helper.log_info(f"Found {len(submissions)} malicious submissions")

            processed = 0
            failed = 0

            for submission in submissions:
                try:
                    result = self._process_submission(submission)
                    if result.get('processed'):
                        processed += 1
                        self.helper.log_info(f"✅ {submission.get('sid')} processed")
                    else:
                        self.helper.log_info(f"⏭️ {submission.get('sid')} skipped: {result.get('reason')}")
                except Exception as e:
                    failed += 1
                    self.helper.log_error(f"❌ {submission.get('sid')} failed: {str(e)}")

            self.helper.log_info(f"Import complete: {processed} processed, {failed} failed")

        except Exception as e:
            self.helper.log_error(f"Import failed: {str(e)}")

    def start(self):
        """Start the connector"""
        try:
            self.helper.log_info("Starting AssemblyLine Import Connector...")

            if self.helper.connect_run_and_terminate:
                self._run_import()
            else:
                self.helper.log_info(f"Continuous mode, interval: {self.import_interval}s")
                while True:
                    try:
                        self._run_import()
                        self.helper.log_info(f"Waiting {self.import_interval}s...")
                        time.sleep(self.import_interval)
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        self.helper.log_error(f"Loop error: {str(e)}")
                        time.sleep(60)

        except Exception as e:
            self.helper.log_error(f"Startup failed: {str(e)}")


if __name__ == "__main__":
    connector = AssemblyLineImportConnector()
    connector.start()
