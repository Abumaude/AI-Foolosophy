"""
MITRE ATT&CK Hypothesis Generator for FTE-HARM Framework

This module bridges the MITRE ATT&CK knowledge base with the FTE-HARM
(Forensic Triage Entity - Hypothesis-driven Automated Risk Measurement)
hypothesis scoring system.

Author: FTE-HARM Research
Version: 1.0.0
"""

import json
import os
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import urllib.request
import warnings


# ==============================================================================
# DATA CLASSES AND ENUMS
# ==============================================================================

class ConfidenceLevel(Enum):
    """P_Score confidence levels for triage decisions."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


class TriageDecision(Enum):
    """Triage action based on confidence level."""
    INVESTIGATE_IMMEDIATE = "INVESTIGATE_IMMEDIATE"
    INVESTIGATE_PRIORITY = "INVESTIGATE_PRIORITY"
    INVESTIGATE_STANDARD = "INVESTIGATE_STANDARD"
    MONITOR = "MONITOR"
    ARCHIVE = "ARCHIVE"


@dataclass
class TechniqueDetails:
    """Container for extracted MITRE ATT&CK technique details."""
    id: str
    name: str
    description: str
    tactics: List[str]
    data_sources: List[str]
    data_components: List[str]
    platforms: List[str]
    detection: str

    def __str__(self):
        return f"{self.id}: {self.name}"


@dataclass
class HypothesisConfig:
    """FTE-HARM hypothesis configuration derived from ATT&CK technique."""
    name: str
    mitre_technique: str
    mitre_tactic: str
    description: str
    weights: Dict[str, float]
    critical_entity: str
    penalty_factor: float
    threshold: float
    data_sources: List[str]
    platforms: List[str]

    def validate(self) -> bool:
        """Validate that weights sum approximately to 1.0."""
        total = sum(self.weights.values())
        return 0.95 <= total <= 1.05


@dataclass
class PScoreResult:
    """Result of P_Score calculation."""
    p_score: float
    confidence: ConfidenceLevel
    triage_decision: TriageDecision
    entities_present: List[str]
    entities_missing: List[str]
    critical_entity_present: bool
    mitre_technique: str
    mitre_tactic: str
    weighted_contributions: Dict[str, float]


# ==============================================================================
# ENTITY MAPPING CONFIGURATION
# ==============================================================================

# Comprehensive mapping between ATT&CK data sources and FTE-HARM's 22 entity types
ATTACK_TO_ENTITY_MAPPING: Dict[str, List[str]] = {
    # Process-related data sources
    'Process': ['Process', 'ProcessID'],
    'Process Creation': ['Process', 'ProcessID', 'DateTime'],
    'Process Termination': ['Process', 'ProcessID', 'DateTime'],
    'Command': ['Process', 'Action'],
    'Command Execution': ['Process', 'Action', 'Username'],
    'OS API Execution': ['Process', 'Action'],
    'Script Execution': ['Process', 'Action', 'Object'],

    # Authentication and User data sources
    'User Account': ['Username'],
    'User Account Authentication': ['Username', 'Action', 'Status', 'AuthenticationType'],
    'User Account Creation': ['Username', 'DateTime', 'Action'],
    'User Account Deletion': ['Username', 'DateTime', 'Action'],
    'User Account Modification': ['Username', 'DateTime', 'Action'],
    'Logon Session': ['Username', 'DateTime', 'SessionID'],
    'Logon Session Creation': ['Username', 'DateTime', 'SessionID', 'Action'],
    'Logon Session Metadata': ['Username', 'SessionID'],
    'Active Directory': ['Username', 'Object'],

    # Network data sources
    'Network Traffic': ['IPAddress', 'Port', 'Protocol'],
    'Network Traffic Content': ['IPAddress', 'Port', 'Protocol', 'DNSName'],
    'Network Traffic Flow': ['IPAddress', 'Port', 'Protocol', 'ByteCount'],
    'Network Connection Creation': ['IPAddress', 'Port', 'Protocol', 'DateTime'],
    'Network Connection': ['IPAddress', 'Port', 'Protocol'],
    'Network Share': ['IPAddress', 'Object', 'Username'],

    # DNS data sources
    'DNS': ['DNSName', 'IPAddress', 'Action'],
    'Domain Name': ['DNSName'],

    # File and Object data sources
    'File': ['Object', 'DateTime'],
    'File Access': ['Object', 'DateTime', 'Username', 'Action'],
    'File Creation': ['Object', 'DateTime', 'Action'],
    'File Deletion': ['Object', 'DateTime', 'Action'],
    'File Metadata': ['Object'],
    'File Modification': ['Object', 'DateTime', 'Action'],
    'Windows Registry': ['Object', 'Action'],
    'Windows Registry Key Access': ['Object', 'Action', 'DateTime'],
    'Windows Registry Key Creation': ['Object', 'Action', 'DateTime'],
    'Windows Registry Key Deletion': ['Object', 'Action', 'DateTime'],
    'Windows Registry Key Modification': ['Object', 'Action', 'DateTime'],

    # Service and Application data sources
    'Application Log': ['DateTime', 'Severity', 'Service', 'Action'],
    'Application Log Content': ['DateTime', 'Severity', 'Service'],
    'Service': ['Service', 'Process'],
    'Service Creation': ['Service', 'Process', 'DateTime'],
    'Service Metadata': ['Service'],
    'Service Modification': ['Service', 'DateTime', 'Action'],

    # Driver and Kernel data sources
    'Driver': ['Process', 'Object'],
    'Driver Load': ['Process', 'Object', 'DateTime'],
    'Kernel': ['Process'],
    'Module': ['Process', 'Object'],
    'Module Load': ['Process', 'Object', 'DateTime'],

    # Cloud and Container data sources
    'Cloud Service': ['Service', 'Action'],
    'Container': ['Process', 'Object'],
    'Instance': ['Object', 'IPAddress'],
    'Image': ['Object'],
    'Pod': ['Object', 'Service'],
    'Snapshot': ['Object', 'DateTime'],
    'Volume': ['Object'],

    # Scheduled Task and WMI
    'Scheduled Job': ['Process', 'DateTime', 'Action'],
    'Scheduled Job Creation': ['Process', 'DateTime', 'Action'],
    'Scheduled Job Metadata': ['Process', 'DateTime'],
    'Scheduled Job Modification': ['Process', 'DateTime', 'Action'],
    'WMI': ['Process', 'Action'],
    'WMI Creation': ['Process', 'DateTime', 'Action'],

    # Firmware and Hardware
    'Firmware': ['Object'],
    'Firmware Modification': ['Object', 'DateTime', 'Action'],

    # Error and Status
    'Error': ['Error', 'Status'],
    'Status': ['Status', 'Severity'],

    # Firewall
    'Firewall': ['IPAddress', 'Port', 'Protocol', 'Action'],
    'Firewall Disable': ['Action', 'DateTime'],
    'Firewall Enumeration': ['Action', 'DateTime'],
    'Firewall Rule Modification': ['Action', 'DateTime', 'Object'],

    # Mail and Web
    'Mail Server': ['Object', 'Username'],
    'Malware Repository': ['Object'],
    'Web Credential': ['Username', 'Object'],

    # Sensor Health
    'Sensor Health': ['Status', 'DateTime', 'Service'],
    'Host Status': ['Status', 'DateTime']
}

# The complete set of 22 FTE-HARM entity types
FTE_HARM_ENTITIES = [
    'DateTime', 'System', 'Service', 'Process', 'ProcessID',
    'Username', 'Message', 'IPAddress', 'Port', 'Protocol',
    'DNSName', 'URL', 'Object', 'Action', 'Status',
    'Error', 'Severity', 'SessionID', 'AuthenticationType',
    'ByteCount', 'EventID', 'LogLevel'
]

# Tactic-specific threshold mappings
TACTIC_THRESHOLDS: Dict[str, float] = {
    'Privilege Escalation': 0.50,
    'Lateral Movement': 0.50,
    'Exfiltration': 0.55,
    'Command And Control': 0.55,
    'Initial Access': 0.50,
    'Discovery': 0.45,
    'Persistence': 0.50,
    'Defense Evasion': 0.50,
    'Credential Access': 0.50,
    'Execution': 0.45,
    'Collection': 0.50,
    'Impact': 0.55,
    'Resource Development': 0.45,
    'Reconnaissance': 0.40
}

# Critical entity indicators based on technique characteristics
CRITICAL_ENTITY_INDICATORS: Dict[str, List[str]] = {
    'Process': ['sudo', 'su', 'process', 'command', 'execution', 'spawn', 'shell', 'script'],
    'Username': ['user', 'account', 'privilege', 'escalation', 'credential', 'authentication', 'login'],
    'DNSName': ['dns', 'domain', 'query', 'resolution', 'dga', 'beacon'],
    'IPAddress': ['network', 'connection', 'traffic', 'address', 'remote', 'c2', 'exfil'],
    'Action': ['authentication', 'login', 'access', 'failed', 'successful', 'create', 'modify', 'delete'],
    'Object': ['file', 'registry', 'key', 'path', 'artifact'],
    'Service': ['service', 'daemon', 'application']
}


# ==============================================================================
# ATTACK SCENARIO DEFINITIONS
# ==============================================================================

ATTACK_SCENARIOS: Dict[str, List[str]] = {
    'privilege_escalation': [
        'T1548.003',  # Sudo and Su
        'T1548.002',  # Bypass User Account Control
        'T1068',      # Exploitation for Privilege Escalation
        'T1548.001',  # Setuid and Setgid
        'T1134.001',  # Token Impersonation/Theft
        'T1055',      # Process Injection
    ],

    'lateral_movement': [
        'T1021.004',  # SSH
        'T1021.002',  # SMB/Windows Admin Shares
        'T1021.001',  # Remote Desktop Protocol
        'T1563.001',  # SSH Hijacking
        'T1563.002',  # RDP Hijacking
        'T1210',      # Exploitation of Remote Services
    ],

    'exfiltration': [
        'T1048.003',  # Exfiltration Over Unencrypted Non-C2 Protocol
        'T1041',      # Exfiltration Over C2 Channel
        'T1567.002',  # Exfiltration to Cloud Storage
        'T1048.001',  # Exfiltration Over Symmetric Encrypted Non-C2 Protocol
        'T1020',      # Automated Exfiltration
        'T1030',      # Data Transfer Size Limits
    ],

    'dns_abuse': [
        'T1071.004',  # DNS Application Layer Protocol
        'T1568.002',  # Domain Generation Algorithms
        'T1584.001',  # Compromise Infrastructure: Domains
        'T1583.001',  # Acquire Infrastructure: Domains
        'T1568.001',  # Fast Flux DNS
        'T1071.001',  # Web Protocols
    ],

    'credential_access': [
        'T1110.001',  # Brute Force: Password Guessing
        'T1110.003',  # Brute Force: Password Spraying
        'T1552.001',  # Unsecured Credentials: Credentials In Files
        'T1003.001',  # OS Credential Dumping: LSASS Memory
        'T1558.003',  # Kerberoasting
        'T1555.003',  # Credentials from Web Browsers
    ],

    'command_and_control': [
        'T1071.001',  # Web Protocols
        'T1071.004',  # DNS
        'T1573.001',  # Encrypted Channel: Symmetric Cryptography
        'T1105',      # Ingress Tool Transfer
        'T1571',      # Non-Standard Port
        'T1572',      # Protocol Tunneling
    ],

    'persistence': [
        'T1053.005',  # Scheduled Task/Job: Scheduled Task
        'T1547.001',  # Boot or Logon Autostart Execution: Registry Run Keys
        'T1543.003',  # Create or Modify System Process: Windows Service
        'T1136.001',  # Create Account: Local Account
        'T1078.003',  # Valid Accounts: Local Accounts
        'T1505.003',  # Server Software Component: Web Shell
    ],

    'defense_evasion': [
        'T1070.001',  # Indicator Removal: Clear Windows Event Logs
        'T1562.001',  # Impair Defenses: Disable or Modify Tools
        'T1036.005',  # Masquerading: Match Legitimate Name or Location
        'T1027',      # Obfuscated Files or Information
        'T1218.011',  # System Binary Proxy Execution: Rundll32
        'T1140',      # Deobfuscate/Decode Files or Information
    ],

    'discovery': [
        'T1087.001',  # Account Discovery: Local Account
        'T1083',      # File and Directory Discovery
        'T1057',      # Process Discovery
        'T1018',      # Remote System Discovery
        'T1082',      # System Information Discovery
        'T1049',      # System Network Connections Discovery
    ]
}


# ==============================================================================
# MITRE ATT&CK DATA LOADER
# ==============================================================================

class MitreAttackLoader:
    """
    Loader for MITRE ATT&CK STIX data.

    Can load from local file or download from MITRE's official repository.
    """

    ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def __init__(self, data_path: Optional[str] = None):
        """
        Initialize the ATT&CK data loader.

        Args:
            data_path: Path to local enterprise-attack.json file.
                      If None, will download from MITRE.
        """
        self.data_path = data_path
        self.stix_data = None
        self._techniques_cache: Dict[str, Dict] = {}
        self._tactics_cache: Dict[str, Dict] = {}
        self._data_sources_cache: Dict[str, Dict] = {}

    def load(self) -> bool:
        """
        Load ATT&CK STIX data from file or download.

        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.data_path and os.path.exists(self.data_path):
                print(f"Loading ATT&CK data from {self.data_path}...")
                with open(self.data_path, 'r', encoding='utf-8') as f:
                    self.stix_data = json.load(f)
            else:
                print("Downloading ATT&CK data from MITRE repository...")
                self._download_attack_data()

            self._build_caches()
            print(f"✓ Loaded {len(self._techniques_cache)} techniques")
            print(f"✓ Loaded {len(self._tactics_cache)} tactics")
            return True

        except Exception as e:
            print(f"✗ Failed to load ATT&CK data: {e}")
            return False

    def _download_attack_data(self):
        """Download ATT&CK STIX data from MITRE's repository."""
        try:
            with urllib.request.urlopen(self.ATTACK_STIX_URL, timeout=60) as response:
                data = response.read().decode('utf-8')
                self.stix_data = json.loads(data)

                # Optionally save for future use
                save_path = "enterprise-attack.json"
                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump(self.stix_data, f)
                print(f"✓ Saved ATT&CK data to {save_path}")

        except Exception as e:
            raise RuntimeError(f"Failed to download ATT&CK data: {e}")

    def _build_caches(self):
        """Build lookup caches for techniques, tactics, and data sources."""
        if not self.stix_data or 'objects' not in self.stix_data:
            raise ValueError("No STIX data loaded")

        for obj in self.stix_data['objects']:
            obj_type = obj.get('type', '')

            if obj_type == 'attack-pattern':
                # This is a technique
                external_refs = obj.get('external_references', [])
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id', '')
                        if technique_id:
                            self._techniques_cache[technique_id] = obj
                            break

            elif obj_type == 'x-mitre-tactic':
                # This is a tactic
                external_refs = obj.get('external_references', [])
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        tactic_id = ref.get('external_id', '')
                        if tactic_id:
                            self._tactics_cache[tactic_id] = obj
                            break

            elif obj_type == 'x-mitre-data-source':
                # This is a data source
                name = obj.get('name', '')
                if name:
                    self._data_sources_cache[name] = obj

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """
        Get technique by ID (e.g., 'T1548.003').

        Args:
            technique_id: MITRE ATT&CK technique ID.

        Returns:
            Technique STIX object or None.
        """
        return self._techniques_cache.get(technique_id)

    def get_all_techniques(self) -> List[Dict]:
        """Get all techniques."""
        return list(self._techniques_cache.values())

    def get_all_technique_ids(self) -> List[str]:
        """Get all technique IDs."""
        return list(self._techniques_cache.keys())

    def get_tactic(self, tactic_id: str) -> Optional[Dict]:
        """Get tactic by ID (e.g., 'TA0004')."""
        return self._tactics_cache.get(tactic_id)

    def get_data_source(self, name: str) -> Optional[Dict]:
        """Get data source by name."""
        return self._data_sources_cache.get(name)

    def search_techniques(self, keyword: str) -> List[Tuple[str, str]]:
        """
        Search techniques by keyword in name or description.

        Args:
            keyword: Search keyword.

        Returns:
            List of (technique_id, name) tuples.
        """
        results = []
        keyword_lower = keyword.lower()

        for tech_id, tech in self._techniques_cache.items():
            name = tech.get('name', '').lower()
            description = tech.get('description', '').lower()

            if keyword_lower in name or keyword_lower in description:
                results.append((tech_id, tech.get('name', '')))

        return results


# ==============================================================================
# TECHNIQUE EXTRACTOR
# ==============================================================================

class TechniqueExtractor:
    """Extract comprehensive details from ATT&CK techniques."""

    def __init__(self, attack_loader: MitreAttackLoader):
        """
        Initialize extractor with loaded ATT&CK data.

        Args:
            attack_loader: Loaded MitreAttackLoader instance.
        """
        self.loader = attack_loader

    def extract(self, technique_id: str) -> Optional[TechniqueDetails]:
        """
        Extract comprehensive details for a specific ATT&CK technique.

        Args:
            technique_id: ATT&CK technique ID (e.g., "T1548.003").

        Returns:
            TechniqueDetails object or None if not found.
        """
        technique = self.loader.get_technique(technique_id)

        if not technique:
            return None

        # Extract basic info
        name = technique.get('name', '')
        description = technique.get('description', '')
        platforms = technique.get('x_mitre_platforms', [])
        detection = technique.get('x_mitre_detection', '')

        # Extract tactics from kill chain phases
        tactics = []
        kill_chain = technique.get('kill_chain_phases', [])
        for phase in kill_chain:
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactic_name = phase.get('phase_name', '')
                # Convert from hyphenated to title case
                formatted_tactic = tactic_name.replace('-', ' ').title()
                tactics.append(formatted_tactic)

        # Extract data sources and components
        data_sources = []
        data_components = []

        # Try newer format first (x_mitre_data_sources as list of strings)
        raw_data_sources = technique.get('x_mitre_data_sources', [])

        for ds in raw_data_sources:
            if isinstance(ds, str):
                # Format: "Data Source: Data Component"
                if ':' in ds:
                    source, component = ds.split(':', 1)
                    data_sources.append(source.strip())
                    data_components.append(component.strip())
                else:
                    data_sources.append(ds.strip())

        # Remove duplicates while preserving order
        data_sources = list(dict.fromkeys(data_sources))
        data_components = list(dict.fromkeys(data_components))

        return TechniqueDetails(
            id=technique_id,
            name=name,
            description=description,
            tactics=tactics,
            data_sources=data_sources,
            data_components=data_components,
            platforms=platforms,
            detection=detection
        )

    def extract_batch(self, technique_ids: List[str]) -> Dict[str, TechniqueDetails]:
        """
        Extract details for multiple techniques.

        Args:
            technique_ids: List of technique IDs.

        Returns:
            Dict mapping technique IDs to TechniqueDetails.
        """
        results = {}
        for tech_id in technique_ids:
            details = self.extract(tech_id)
            if details:
                results[tech_id] = details
        return results


# ==============================================================================
# ENTITY MAPPER
# ==============================================================================

class EntityMapper:
    """Map ATT&CK data sources to FTE-HARM forensic entities."""

    def __init__(self, custom_mapping: Optional[Dict[str, List[str]]] = None):
        """
        Initialize entity mapper.

        Args:
            custom_mapping: Optional custom mapping to override defaults.
        """
        self.mapping = custom_mapping or ATTACK_TO_ENTITY_MAPPING

    def map_data_sources(self, data_sources: List[str]) -> List[str]:
        """
        Map ATT&CK data sources to FTE-HARM entity types.

        Args:
            data_sources: List of ATT&CK data sources.

        Returns:
            List of relevant FTE-HARM entity types.
        """
        entities = set()

        for source in data_sources:
            source_lower = source.lower()

            # Check each mapping key
            for attack_source, entity_types in self.mapping.items():
                if attack_source.lower() in source_lower or source_lower in attack_source.lower():
                    entities.update(entity_types)

        # DateTime is always relevant for temporal context
        entities.add('DateTime')

        # Validate entities are in our 22-entity set
        valid_entities = [e for e in entities if e in FTE_HARM_ENTITIES]

        return valid_entities

    def map_data_components(self, data_components: List[str]) -> List[str]:
        """
        Map ATT&CK data components to FTE-HARM entity types.

        Args:
            data_components: List of ATT&CK data components.

        Returns:
            List of additional relevant entity types.
        """
        entities = set()

        # Component-specific mappings
        component_keywords = {
            'creation': ['DateTime', 'Action'],
            'modification': ['DateTime', 'Action'],
            'deletion': ['DateTime', 'Action'],
            'access': ['Action', 'Username'],
            'authentication': ['Username', 'Action', 'AuthenticationType'],
            'connection': ['IPAddress', 'Port', 'Protocol'],
            'process': ['Process', 'ProcessID'],
            'command': ['Process', 'Action'],
            'content': ['Object'],
            'metadata': ['Object'],
            'enumeration': ['Action']
        }

        for component in data_components:
            component_lower = component.lower()
            for keyword, entity_types in component_keywords.items():
                if keyword in component_lower:
                    entities.update(entity_types)

        return [e for e in entities if e in FTE_HARM_ENTITIES]


# ==============================================================================
# WEIGHT GENERATOR
# ==============================================================================

class WeightGenerator:
    """Generate entity weights for FTE-HARM hypothesis configurations."""

    def __init__(self,
                 critical_indicators: Optional[Dict[str, List[str]]] = None,
                 datetime_weight: float = 0.10):
        """
        Initialize weight generator.

        Args:
            critical_indicators: Custom critical entity indicators.
            datetime_weight: Fixed weight for DateTime entity.
        """
        self.critical_indicators = critical_indicators or CRITICAL_ENTITY_INDICATORS
        self.datetime_weight = datetime_weight

    def generate(self,
                 entities: List[str],
                 technique_details: TechniqueDetails) -> Dict[str, float]:
        """
        Generate entity weights based on ATT&CK technique characteristics.

        Weighting strategy:
        - Critical entities (directly mentioned in technique): 0.30-0.40
        - Strong entities (required for detection): 0.20-0.25
        - Supporting entities (contextual): 0.10-0.15
        - Temporal context (DateTime): Fixed weight

        Args:
            entities: List of relevant entity types.
            technique_details: ATT&CK technique details.

        Returns:
            Dict of entity weights summing to ~1.0.
        """
        weights = {}
        technique_text = (technique_details.name + ' ' +
                         technique_details.description + ' ' +
                         technique_details.detection).lower()

        # Categorize entities
        critical = []
        strong = []
        supporting = []

        for entity in entities:
            if entity == 'DateTime':
                continue  # Handle separately

            # Check if entity is critical for this technique
            is_critical = False
            if entity in self.critical_indicators:
                for keyword in self.critical_indicators[entity]:
                    if keyword in technique_text:
                        is_critical = True
                        break

            if is_critical:
                critical.append(entity)
            elif entity in ['Process', 'Username', 'Action', 'DNSName', 'IPAddress', 'Service']:
                strong.append(entity)
            else:
                supporting.append(entity)

        # Calculate available weight (reserve DateTime weight)
        available_weight = 1.0 - self.datetime_weight

        # Distribute weights
        num_critical = len(critical)
        num_strong = len(strong)
        num_supporting = len(supporting)

        if num_critical > 0:
            # Critical entities get 35% each (up to 70% total)
            critical_weight = min(0.35, available_weight * 0.5 / num_critical)
            for entity in critical:
                weights[entity] = critical_weight
            available_weight -= critical_weight * num_critical

        if num_strong > 0:
            # Strong entities get remaining weight more evenly
            strong_weight = min(0.25, available_weight * 0.7 / num_strong)
            for entity in strong:
                weights[entity] = strong_weight
            available_weight -= strong_weight * num_strong

        if num_supporting > 0 and available_weight > 0:
            # Supporting entities split remaining weight
            supporting_weight = available_weight / num_supporting
            for entity in supporting:
                weights[entity] = supporting_weight

        # Add DateTime weight
        weights['DateTime'] = self.datetime_weight

        # Normalize to ensure sum is exactly 1.0
        total = sum(weights.values())
        if total > 0:
            weights = {k: round(v / total, 3) for k, v in weights.items()}

        # Final adjustment to ensure sum is 1.0
        adjustment = 1.0 - sum(weights.values())
        if adjustment != 0 and weights:
            max_entity = max(weights.keys(), key=lambda k: weights[k])
            weights[max_entity] = round(weights[max_entity] + adjustment, 3)

        return weights

    def identify_critical_entity(self,
                                  weights: Dict[str, float],
                                  technique_details: TechniqueDetails) -> str:
        """
        Identify the critical entity for a hypothesis.

        Args:
            weights: Generated weights.
            technique_details: Technique details.

        Returns:
            Name of critical entity.
        """
        # Remove DateTime from consideration for critical entity
        non_temporal_weights = {k: v for k, v in weights.items() if k != 'DateTime'}

        if not non_temporal_weights:
            return 'DateTime'

        return max(non_temporal_weights.keys(), key=lambda k: non_temporal_weights[k])


# ==============================================================================
# HYPOTHESIS GENERATOR
# ==============================================================================

class HypothesisGenerator:
    """Generate FTE-HARM hypothesis configurations from ATT&CK techniques."""

    def __init__(self,
                 attack_loader: MitreAttackLoader,
                 default_penalty_factor: float = 0.20):
        """
        Initialize hypothesis generator.

        Args:
            attack_loader: Loaded MitreAttackLoader instance.
            default_penalty_factor: Default penalty for missing critical entity.
        """
        self.loader = attack_loader
        self.extractor = TechniqueExtractor(attack_loader)
        self.entity_mapper = EntityMapper()
        self.weight_generator = WeightGenerator()
        self.default_penalty_factor = default_penalty_factor

    def generate(self,
                 technique_id: str,
                 hypothesis_name: Optional[str] = None) -> Optional[HypothesisConfig]:
        """
        Generate complete FTE-HARM hypothesis configuration from ATT&CK technique.

        Args:
            technique_id: ATT&CK technique ID.
            hypothesis_name: Optional custom name.

        Returns:
            HypothesisConfig or None if technique not found.
        """
        # Extract technique details
        details = self.extractor.extract(technique_id)
        if not details:
            return None

        # Map to entities
        entities_from_sources = self.entity_mapper.map_data_sources(details.data_sources)
        entities_from_components = self.entity_mapper.map_data_components(details.data_components)

        # Combine and deduplicate
        all_entities = list(set(entities_from_sources + entities_from_components))

        # Ensure we have at least DateTime and one other entity
        if len(all_entities) < 2:
            all_entities = ['DateTime', 'Action', 'Process']

        # Generate weights
        weights = self.weight_generator.generate(all_entities, details)

        # Identify critical entity
        critical_entity = self.weight_generator.identify_critical_entity(weights, details)

        # Determine threshold based on tactic
        threshold = 0.50  # Default
        for tactic in details.tactics:
            if tactic in TACTIC_THRESHOLDS:
                threshold = TACTIC_THRESHOLDS[tactic]
                break

        # Generate name if not provided
        if not hypothesis_name:
            safe_name = details.name.lower().replace(' ', '_').replace('/', '_').replace(':', '')
            hypothesis_name = f"{technique_id}_{safe_name[:30]}"

        # Truncate description
        description = details.description
        if len(description) > 250:
            description = description[:247] + "..."

        return HypothesisConfig(
            name=hypothesis_name,
            mitre_technique=technique_id,
            mitre_tactic=details.tactics[0] if details.tactics else "Unknown",
            description=description,
            weights=weights,
            critical_entity=critical_entity,
            penalty_factor=self.default_penalty_factor,
            threshold=threshold,
            data_sources=details.data_sources,
            platforms=details.platforms
        )

    def generate_scenario(self,
                          scenario_name: str,
                          technique_ids: Optional[List[str]] = None) -> Dict[str, HypothesisConfig]:
        """
        Generate all hypotheses for a specific attack scenario.

        Args:
            scenario_name: Name of scenario (e.g., 'privilege_escalation').
            technique_ids: Optional list of technique IDs. If None, uses predefined.

        Returns:
            Dict mapping hypothesis names to configurations.
        """
        if technique_ids is None:
            technique_ids = ATTACK_SCENARIOS.get(scenario_name, [])

        if not technique_ids:
            warnings.warn(f"No techniques defined for scenario: {scenario_name}")
            return {}

        hypotheses = {}

        for idx, technique_id in enumerate(technique_ids, start=1):
            hypothesis_name = f"H{idx}_{scenario_name}"

            try:
                config = self.generate(technique_id, hypothesis_name)
                if config:
                    hypotheses[hypothesis_name] = config
                    print(f"✓ Generated: {hypothesis_name} ({technique_id})")
                else:
                    print(f"✗ Not found: {technique_id}")
            except Exception as e:
                print(f"✗ Failed: {technique_id} - {e}")

        return hypotheses

    def generate_all_scenarios(self) -> Dict[str, Dict[str, HypothesisConfig]]:
        """
        Generate hypotheses for all predefined attack scenarios.

        Returns:
            Nested dict: scenario_name -> hypothesis_name -> config
        """
        all_hypotheses = {}

        for scenario_name in ATTACK_SCENARIOS.keys():
            print(f"\n--- Generating {scenario_name} hypotheses ---")
            hypotheses = self.generate_scenario(scenario_name)
            all_hypotheses[scenario_name] = hypotheses

        return all_hypotheses


# ==============================================================================
# P_SCORE CALCULATOR
# ==============================================================================

class PScoreCalculator:
    """Calculate P_Score using ATT&CK-generated hypothesis configurations."""

    # Confidence thresholds (permissive for triage)
    HIGH_THRESHOLD = 0.65
    MEDIUM_THRESHOLD = 0.50
    LOW_THRESHOLD = 0.35

    def __init__(self):
        """Initialize P_Score calculator."""
        pass

    def calculate(self,
                  entities: Dict[str, List[Any]],
                  hypothesis: HypothesisConfig) -> PScoreResult:
        """
        Calculate P_Score using ATT&CK-generated hypothesis configuration.

        P_Score = (Σ(W_i × E_i)) × (1 - P_F) if critical entity missing
        P_Score = Σ(W_i × E_i) if critical entity present

        Args:
            entities: Extracted entities {entity_type: [values]}.
            hypothesis: ATT&CK-generated hypothesis configuration.

        Returns:
            PScoreResult with score, confidence, and details.
        """
        weights = hypothesis.weights
        critical_entity = hypothesis.critical_entity
        penalty_factor = hypothesis.penalty_factor

        # Calculate weighted sum
        total_score = 0.0
        entities_present = []
        entities_missing = []
        weighted_contributions = {}

        for entity_type, weight in weights.items():
            if entity_type in entities and entities[entity_type]:
                total_score += weight
                entities_present.append(entity_type)
                weighted_contributions[entity_type] = weight
            else:
                entities_missing.append(entity_type)
                weighted_contributions[entity_type] = 0.0

        # Apply penalty if critical entity missing
        critical_present = critical_entity in entities_present

        if not critical_present:
            p_score = total_score * (1 - penalty_factor)
        else:
            p_score = total_score

        # Round to 3 decimal places
        p_score = round(p_score, 3)

        # Determine confidence level
        if p_score >= self.HIGH_THRESHOLD:
            confidence = ConfidenceLevel.HIGH
            triage_decision = TriageDecision.INVESTIGATE_IMMEDIATE
        elif p_score >= self.MEDIUM_THRESHOLD:
            confidence = ConfidenceLevel.MEDIUM
            triage_decision = TriageDecision.INVESTIGATE_PRIORITY
        elif p_score >= self.LOW_THRESHOLD:
            confidence = ConfidenceLevel.LOW
            triage_decision = TriageDecision.INVESTIGATE_STANDARD
        else:
            confidence = ConfidenceLevel.INSUFFICIENT
            triage_decision = TriageDecision.MONITOR

        return PScoreResult(
            p_score=p_score,
            confidence=confidence,
            triage_decision=triage_decision,
            entities_present=entities_present,
            entities_missing=entities_missing,
            critical_entity_present=critical_present,
            mitre_technique=hypothesis.mitre_technique,
            mitre_tactic=hypothesis.mitre_tactic,
            weighted_contributions=weighted_contributions
        )

    def calculate_multi_hypothesis(self,
                                   entities: Dict[str, List[Any]],
                                   hypotheses: Dict[str, HypothesisConfig]) -> Dict[str, PScoreResult]:
        """
        Calculate P_Score against multiple hypotheses.

        Args:
            entities: Extracted entities.
            hypotheses: Dict of hypothesis configurations.

        Returns:
            Dict mapping hypothesis names to PScoreResults.
        """
        results = {}
        for name, hypothesis in hypotheses.items():
            results[name] = self.calculate(entities, hypothesis)
        return results

    def get_best_match(self,
                       entities: Dict[str, List[Any]],
                       hypotheses: Dict[str, HypothesisConfig]) -> Tuple[str, PScoreResult]:
        """
        Find the best matching hypothesis for given entities.

        Args:
            entities: Extracted entities.
            hypotheses: Dict of hypothesis configurations.

        Returns:
            Tuple of (hypothesis_name, PScoreResult) for best match.
        """
        results = self.calculate_multi_hypothesis(entities, hypotheses)

        if not results:
            return None, None

        best_name = max(results.keys(), key=lambda k: results[k].p_score)
        return best_name, results[best_name]


# ==============================================================================
# HYPOTHESIS TABLE GENERATOR
# ==============================================================================

class HypothesisTableGenerator:
    """Generate formatted hypothesis tables for documentation."""

    def to_markdown(self, hypotheses: Dict[str, HypothesisConfig]) -> str:
        """
        Generate formatted markdown table for thesis documentation.

        Args:
            hypotheses: Dict of generated hypotheses.

        Returns:
            Formatted markdown table string.
        """
        lines = []
        lines.append("| Hypothesis | MITRE ID | Tactic | Critical Entity | Threshold | Top Entity Weights |")
        lines.append("|------------|----------|--------|-----------------|-----------|-------------------|")

        for hyp_name, config in hypotheses.items():
            # Format top 3 weights
            sorted_weights = sorted(
                config.weights.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]
            weights_str = ", ".join([f"{e}({w:.2f})" for e, w in sorted_weights])

            row = [
                hyp_name,
                config.mitre_technique,
                config.mitre_tactic[:20],
                config.critical_entity,
                f"{config.threshold:.2f}",
                weights_str
            ]

            lines.append("| " + " | ".join(row) + " |")

        return "\n".join(lines)

    def to_csv(self, hypotheses: Dict[str, HypothesisConfig]) -> str:
        """
        Generate CSV format for hypothesis configurations.

        Args:
            hypotheses: Dict of generated hypotheses.

        Returns:
            CSV formatted string.
        """
        lines = []
        header = "Name,MITRE_ID,Tactic,Critical_Entity,Threshold,Penalty_Factor,Weights"
        lines.append(header)

        for hyp_name, config in hypotheses.items():
            weights_json = json.dumps(config.weights)
            row = [
                hyp_name,
                config.mitre_technique,
                config.mitre_tactic,
                config.critical_entity,
                str(config.threshold),
                str(config.penalty_factor),
                f'"{weights_json}"'
            ]
            lines.append(",".join(row))

        return "\n".join(lines)

    def to_json(self, hypotheses: Dict[str, HypothesisConfig]) -> str:
        """
        Generate JSON format for hypothesis configurations.

        Args:
            hypotheses: Dict of generated hypotheses.

        Returns:
            JSON formatted string.
        """
        output = {}
        for hyp_name, config in hypotheses.items():
            output[hyp_name] = {
                'name': config.name,
                'mitre_technique': config.mitre_technique,
                'mitre_tactic': config.mitre_tactic,
                'description': config.description,
                'weights': config.weights,
                'critical_entity': config.critical_entity,
                'penalty_factor': config.penalty_factor,
                'threshold': config.threshold,
                'data_sources': config.data_sources,
                'platforms': config.platforms
            }

        return json.dumps(output, indent=2)

    def to_detailed_report(self, hypotheses: Dict[str, HypothesisConfig]) -> str:
        """
        Generate detailed report for each hypothesis.

        Args:
            hypotheses: Dict of generated hypotheses.

        Returns:
            Detailed report string.
        """
        lines = []

        for hyp_name, config in hypotheses.items():
            lines.append("=" * 80)
            lines.append(f"HYPOTHESIS: {hyp_name}")
            lines.append("=" * 80)
            lines.append(f"MITRE Technique: {config.mitre_technique}")
            lines.append(f"MITRE Tactic: {config.mitre_tactic}")
            lines.append(f"Critical Entity: {config.critical_entity}")
            lines.append(f"Threshold: {config.threshold}")
            lines.append(f"Penalty Factor: {config.penalty_factor}")
            lines.append("")
            lines.append("Description:")
            lines.append(f"  {config.description}")
            lines.append("")
            lines.append("Entity Weights:")
            for entity, weight in sorted(config.weights.items(), key=lambda x: x[1], reverse=True):
                bar = "█" * int(weight * 20)
                lines.append(f"  {entity:20s}: {weight:.3f} {bar}")
            lines.append("")
            lines.append("Data Sources (ATT&CK):")
            for ds in config.data_sources:
                lines.append(f"  - {ds}")
            lines.append("")
            lines.append("Platforms:")
            lines.append(f"  {', '.join(config.platforms)}")
            lines.append("")

        return "\n".join(lines)


# ==============================================================================
# VALIDATION PIPELINE
# ==============================================================================

class ValidationPipeline:
    """End-to-end validation of ATT&CK-based hypothesis generation."""

    def __init__(self, attack_loader: MitreAttackLoader):
        """
        Initialize validation pipeline.

        Args:
            attack_loader: Loaded MitreAttackLoader instance.
        """
        self.loader = attack_loader
        self.generator = HypothesisGenerator(attack_loader)
        self.calculator = PScoreCalculator()

    def validate_technique_extraction(self, technique_id: str) -> bool:
        """
        Validate that technique details can be extracted.

        Args:
            technique_id: ATT&CK technique ID.

        Returns:
            True if extraction successful.
        """
        extractor = TechniqueExtractor(self.loader)
        details = extractor.extract(technique_id)

        if not details:
            print(f"✗ Failed to extract {technique_id}")
            return False

        print(f"✓ Extracted {technique_id}: {details.name}")
        print(f"  Tactics: {', '.join(details.tactics)}")
        print(f"  Data Sources: {len(details.data_sources)}")
        return True

    def validate_hypothesis_generation(self, technique_id: str) -> bool:
        """
        Validate that hypothesis can be generated.

        Args:
            technique_id: ATT&CK technique ID.

        Returns:
            True if generation successful.
        """
        hypothesis = self.generator.generate(technique_id)

        if not hypothesis:
            print(f"✗ Failed to generate hypothesis for {technique_id}")
            return False

        # Validate weights sum to 1.0
        if not hypothesis.validate():
            print(f"✗ Weights do not sum to 1.0 for {technique_id}")
            return False

        print(f"✓ Generated hypothesis: {hypothesis.name}")
        print(f"  Critical Entity: {hypothesis.critical_entity}")
        print(f"  Weight Sum: {sum(hypothesis.weights.values()):.3f}")
        return True

    def validate_pscore_calculation(self,
                                     technique_id: str,
                                     test_entities: Dict[str, List[Any]]) -> bool:
        """
        Validate P_Score calculation.

        Args:
            technique_id: ATT&CK technique ID.
            test_entities: Test entities to score.

        Returns:
            True if calculation successful.
        """
        hypothesis = self.generator.generate(technique_id)

        if not hypothesis:
            print(f"✗ Failed to generate hypothesis for {technique_id}")
            return False

        result = self.calculator.calculate(test_entities, hypothesis)

        print(f"✓ P_Score calculated: {result.p_score:.3f}")
        print(f"  Confidence: {result.confidence.value}")
        print(f"  Triage Decision: {result.triage_decision.value}")
        print(f"  Entities Present: {', '.join(result.entities_present)}")
        return True

    def run_full_validation(self, test_technique: str = "T1548.003") -> Dict[str, bool]:
        """
        Run full validation pipeline.

        Args:
            test_technique: Technique to use for testing.

        Returns:
            Dict of validation results.
        """
        print("=" * 80)
        print("MITRE ATT&CK TO FTE-HARM PIPELINE VALIDATION")
        print("=" * 80)

        results = {}

        # Test 1: Technique extraction
        print("\n[TEST 1] Technique Extraction")
        results['extraction'] = self.validate_technique_extraction(test_technique)

        # Test 2: Hypothesis generation
        print("\n[TEST 2] Hypothesis Generation")
        results['generation'] = self.validate_hypothesis_generation(test_technique)

        # Test 3: Entity mapping
        print("\n[TEST 3] Entity Mapping")
        mapper = EntityMapper()
        extractor = TechniqueExtractor(self.loader)
        details = extractor.extract(test_technique)
        if details:
            entities = mapper.map_data_sources(details.data_sources)
            print(f"✓ Mapped {len(details.data_sources)} data sources to {len(entities)} entities")
            print(f"  Entities: {', '.join(entities)}")
            results['mapping'] = True
        else:
            results['mapping'] = False

        # Test 4: P_Score calculation
        print("\n[TEST 4] P_Score Calculation")
        test_entities = {
            'DateTime': ['Jan 24 10:30:45'],
            'Process': ['su'],
            'ProcessID': ['1234'],
            'Username': ['admin', 'www-data']
        }
        results['pscore'] = self.validate_pscore_calculation(test_technique, test_entities)

        # Test 5: Batch generation
        print("\n[TEST 5] Batch Hypothesis Generation")
        try:
            hypotheses = self.generator.generate_scenario('privilege_escalation')
            results['batch'] = len(hypotheses) > 0
            print(f"✓ Generated {len(hypotheses)} hypotheses for privilege_escalation")
        except Exception as e:
            results['batch'] = False
            print(f"✗ Batch generation failed: {e}")

        # Summary
        print("\n" + "=" * 80)
        print("VALIDATION SUMMARY")
        print("=" * 80)
        passed = sum(results.values())
        total = len(results)
        print(f"Passed: {passed}/{total}")
        for test, result in results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"  {test}: {status}")

        return results


# ==============================================================================
# CONVENIENCE FUNCTIONS
# ==============================================================================

def quick_generate_hypothesis(technique_id: str,
                               data_path: Optional[str] = None) -> Optional[HypothesisConfig]:
    """
    Quick utility to generate a single hypothesis.

    Args:
        technique_id: ATT&CK technique ID.
        data_path: Optional path to enterprise-attack.json.

    Returns:
        HypothesisConfig or None.
    """
    loader = MitreAttackLoader(data_path)
    if not loader.load():
        return None

    generator = HypothesisGenerator(loader)
    return generator.generate(technique_id)


def quick_score_entities(entities: Dict[str, List[Any]],
                         technique_id: str,
                         data_path: Optional[str] = None) -> Optional[PScoreResult]:
    """
    Quick utility to score entities against a technique.

    Args:
        entities: Dict of extracted entities.
        technique_id: ATT&CK technique ID.
        data_path: Optional path to enterprise-attack.json.

    Returns:
        PScoreResult or None.
    """
    loader = MitreAttackLoader(data_path)
    if not loader.load():
        return None

    generator = HypothesisGenerator(loader)
    hypothesis = generator.generate(technique_id)

    if not hypothesis:
        return None

    calculator = PScoreCalculator()
    return calculator.calculate(entities, hypothesis)


# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    """Main execution for demonstration and testing."""
    print("MITRE ATT&CK Hypothesis Generator for FTE-HARM")
    print("=" * 50)

    # Load ATT&CK data
    loader = MitreAttackLoader()
    if not loader.load():
        print("Failed to load ATT&CK data")
        return

    # Run validation pipeline
    pipeline = ValidationPipeline(loader)
    results = pipeline.run_full_validation("T1548.003")

    # Generate example hypothesis table
    print("\n" + "=" * 80)
    print("EXAMPLE HYPOTHESIS TABLE")
    print("=" * 80)

    generator = HypothesisGenerator(loader)
    hypotheses = generator.generate_scenario('privilege_escalation')

    table_gen = HypothesisTableGenerator()
    print(table_gen.to_markdown(hypotheses))


if __name__ == "__main__":
    main()
