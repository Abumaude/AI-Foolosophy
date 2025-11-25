"""
Transformer Model Loader for NER Entity Extraction

This module provides functionality to load fine-tuned transformer models
from Google Drive and execute inference to extract 22 entity types from
forensic log data for the FTE-HARM framework.

Models supported:
- DistilBERT (distilbert_base_uncased)
- DistilRoBERTa (distilroberta_base) - RECOMMENDED
- RoBERTa Large (roberta_large)
- XLM-RoBERTa Base (xlm_roberta_base)
- XLM-RoBERTa Large (xlm_roberta_large)

Author: FTE-HARM Project
"""

import re
from typing import List, Tuple, Dict, Optional, Any

# ============================================================================
# CONFIGURATION
# ============================================================================

# Model checkpoint paths on Google Drive
TRANSFORMER_MODELS = {
    # DistilBERT (Distilled BERT - Fast, efficient)
    'distilbert': '/content/drive/My Drive/thesis/transformer/distilberta_base_uncased/results/checkpoint-5245',

    # DistilRoBERTa (RECOMMENDED - Best balance of speed and accuracy)
    'distilroberta': '/content/drive/My Drive/thesis/transformer/distilroberta_base/results/checkpoint-5275',

    # RoBERTa Large (High accuracy, slower)
    'roberta_large': '/content/drive/My Drive/thesis/transformer/roberta_large/results/checkpoint-2772',

    # XLM-RoBERTa Base (Multilingual capability)
    'xlm_roberta_base': '/content/drive/My Drive/thesis/transformer/xlm_roberta_base/results/checkpoint-12216',

    # XLM-RoBERTa Large (Best accuracy, slowest)
    'xlm_roberta_large': '/content/drive/My Drive/thesis/transformer/xlm_roberta_large/results/checkpoint-12240',
}

# 22 Entity labels based on BIO tagging scheme
ENTITY_LABELS = [
    'O',                        # 0  - Outside (not an entity)
    'B-Action',                 # 1  - Action/verb (login, failed, accept)
    'B-ApplicationSpecific',    # 2  - App-specific terms
    'B-AuthenticationType',     # 3  - Auth methods (password, publickey)
    'B-DNSName',                # 4  - Domain names (begin)
    'I-DNSName',                # 5  - Domain names (continuation)
    'B-DateTime',               # 6  - Timestamps (begin)
    'I-DateTime',               # 7  - Timestamps (continuation)
    'B-Error',                  # 8  - Error messages (begin)
    'I-Error',                  # 9  - Error messages (continuation)
    'B-IPAddress',              # 10 - IP addresses (begin only, no I- tag)
    'B-Object',                 # 11 - File/object names
    'B-Port',                   # 12 - Port numbers
    'B-Process',                # 13 - Process names (sshd, su, dnsmasq)
    'B-Protocol',               # 14 - Network protocols (TCP, UDP)
    'B-Service',                # 15 - Service names
    'B-SessionID',              # 16 - Session identifiers
    'B-Severity',               # 17 - Log severity (error, warn, info)
    'B-Status',                 # 18 - Status indicators (begin)
    'I-Status',                 # 19 - Status indicators (continuation)
    'B-System',                 # 20 - Hostnames/systems
    'B-Username',               # 21 - User identifiers
]

# Entity types that have I- (Inside) tags and can span multiple tokens
ENTITIES_WITH_I_TAG = {'DNSName', 'DateTime', 'Error', 'Status'}

# Entity types without I- tags that fragment at token boundaries
FRAGMENTED_ENTITY_TYPES = {'IPAddress', 'Process', 'Username', 'System'}

# Create bidirectional mappings
id2label = {i: label for i, label in enumerate(ENTITY_LABELS)}
label2id = {label: i for i, label in enumerate(ENTITY_LABELS)}


# ============================================================================
# TRANSFORMER NER LOADER CLASS
# ============================================================================

class TransformerNERLoader:
    """
    Loader class for transformer-based NER models trained on forensic log data.

    This class handles:
    - Model loading from Google Drive checkpoints
    - Tokenization with offset mapping
    - Model inference with BIO tag correction
    - Hybrid entity extraction (model + regex post-processing)

    Attributes:
        model_name (str): Name of the loaded model
        model: The loaded transformer model
        tokenizer: The loaded tokenizer
        device: The device (CPU/GPU) to run inference on
    """

    def __init__(self, model_name: str = 'distilroberta', device: Optional[str] = None):
        """
        Initialize the TransformerNERLoader.

        Args:
            model_name: Name of the model to load (default: 'distilroberta')
            device: Device to run inference on ('cuda', 'cpu', or None for auto)
        """
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.device = device
        self._is_loaded = False

    def mount_google_drive(self) -> bool:
        """
        Mount Google Drive in Google Colab environment.

        Returns:
            bool: True if mounted successfully, False otherwise
        """
        try:
            from google.colab import drive
            drive.mount('/content/drive')
            print('Google Drive mounted successfully')
            return True
        except ImportError:
            print('Warning: Not running in Google Colab. Skipping drive mount.')
            return False
        except Exception as e:
            print(f'Error mounting Google Drive: {e}')
            return False

    def install_dependencies(self) -> bool:
        """
        Install required dependencies (transformers, torch).

        Returns:
            bool: True if installation successful
        """
        import subprocess
        import sys

        try:
            print('Installing transformers library...')
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', '-q', 'transformers', 'torch'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print('Dependencies installed successfully')
            return True
        except Exception as e:
            print(f'Error installing dependencies: {e}')
            return False

    def load_model(self, model_name: Optional[str] = None, custom_path: Optional[str] = None) -> bool:
        """
        Load transformer model and tokenizer from checkpoint.

        Args:
            model_name: Override the model name set in __init__
            custom_path: Custom path to model checkpoint (overrides model_name)

        Returns:
            bool: True if model loaded successfully
        """
        try:
            from transformers import AutoTokenizer, AutoModelForTokenClassification
            import torch
        except ImportError:
            print('Error: transformers library not installed. Run install_dependencies() first.')
            return False

        # Determine model path
        if custom_path:
            model_path = custom_path
            self.model_name = 'custom'
        else:
            if model_name:
                self.model_name = model_name

            if self.model_name not in TRANSFORMER_MODELS:
                print(f'Error: Unknown model "{self.model_name}"')
                print(f'Available models: {list(TRANSFORMER_MODELS.keys())}')
                return False

            model_path = TRANSFORMER_MODELS[self.model_name]

        print(f'Loading model: {self.model_name}')
        print(f'Path: {model_path}')

        try:
            # Load tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForTokenClassification.from_pretrained(model_path)

            # Set device
            if self.device is None:
                self.device = 'cuda' if torch.cuda.is_available() else 'cpu'

            self.model.to(self.device)
            self.model.eval()

            self._is_loaded = True

            print(f'Model loaded: {type(self.model).__name__}')
            print(f'Number of labels: {self.model.config.num_labels}')
            print(f'Architecture: {self.model.config.model_type}')
            print(f'Device: {self.device}')

            return True

        except Exception as e:
            print(f'Error loading model: {e}')
            return False

    def _correct_bio_tags(self, pred_labels: List[str]) -> List[str]:
        """
        Correct consecutive B- tags of the same entity type.

        The model sometimes predicts consecutive B- tags when it should
        predict B- followed by I- tags. This creates multiple entities
        instead of one continuous entity.

        Args:
            pred_labels: List of predicted BIO labels

        Returns:
            List of corrected BIO labels
        """
        corrected_labels = []
        prev_entity_type = None

        for label in pred_labels:
            if label.startswith('B-'):
                entity_type = label[2:]
                # If same type as previous, convert B- to I-
                if entity_type == prev_entity_type:
                    corrected_labels.append(f'I-{entity_type}')
                else:
                    corrected_labels.append(label)
                    prev_entity_type = entity_type
            elif label.startswith('I-'):
                corrected_labels.append(label)
                prev_entity_type = label[2:]
            else:  # O
                corrected_labels.append(label)
                prev_entity_type = None

        return corrected_labels

    def _extract_model_entities(
        self,
        log_line: str,
        pred_labels: List[str],
        offset_mapping: List[Tuple[int, int]]
    ) -> List[Tuple[str, str]]:
        """
        Extract entities from model predictions using offset mapping.

        Args:
            log_line: Original log text
            pred_labels: Corrected BIO labels
            offset_mapping: Character offset mapping from tokenizer

        Returns:
            List of (entity_type, entity_value) tuples
        """
        entities = []
        current_entity_type = None
        entity_spans = []

        for idx, (label, (start, end)) in enumerate(zip(pred_labels, offset_mapping)):
            # Skip special tokens (CLS, SEP, PAD)
            if start == 0 and end == 0:
                continue

            if label.startswith('B-'):
                # Save previous entity
                if current_entity_type and entity_spans:
                    entity_start = entity_spans[0][0]
                    entity_end = entity_spans[-1][1]
                    entity_value = log_line[entity_start:entity_end].strip()
                    if entity_value:
                        entities.append((current_entity_type, entity_value))

                # Start new entity
                current_entity_type = label[2:]
                entity_spans = [(start, end)]

            elif label.startswith('I-') and current_entity_type:
                entity_type = label[2:]
                if entity_type == current_entity_type:
                    entity_spans.append((start, end))
                else:
                    # Different entity type, save previous
                    if entity_spans:
                        entity_start = entity_spans[0][0]
                        entity_end = entity_spans[-1][1]
                        entity_value = log_line[entity_start:entity_end].strip()
                        if entity_value:
                            entities.append((current_entity_type, entity_value))
                    current_entity_type = entity_type
                    entity_spans = [(start, end)]

            elif label == 'O':
                if current_entity_type and entity_spans:
                    entity_start = entity_spans[0][0]
                    entity_end = entity_spans[-1][1]
                    entity_value = log_line[entity_start:entity_end].strip()
                    if entity_value:
                        entities.append((current_entity_type, entity_value))
                current_entity_type = None
                entity_spans = []

        # Save last entity
        if current_entity_type and entity_spans:
            entity_start = entity_spans[0][0]
            entity_end = entity_spans[-1][1]
            entity_value = log_line[entity_start:entity_end].strip()
            if entity_value:
                entities.append((current_entity_type, entity_value))

        return entities

    def _extract_regex_entities(self, log_line: str) -> List[Tuple[str, str]]:
        """
        Extract entities using regex patterns for fragmented entity types.

        This handles entity types that don't have I- tags and fragment
        at token boundaries when using pure model extraction.

        Args:
            log_line: Log text to extract from

        Returns:
            List of (entity_type, entity_value) tuples
        """
        entities = []

        # IP Addresses (complete - model fragments these)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for match in re.finditer(ip_pattern, log_line):
            entities.append(('IPAddress', match.group()))

        # DNS Names (complete domains)
        dns_pattern = r'\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b'
        for match in re.finditer(dns_pattern, log_line, re.IGNORECASE):
            domain = match.group()
            # Exclude IPs that might match pattern
            if not re.match(r'^\d+\.\d+', domain):
                entities.append(('DNSName', domain))

        # Process names with PIDs: sshd[1234], dnsmasq[567], su[890]
        process_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_-]*)\[(\d+)\]'
        for match in re.finditer(process_pattern, log_line):
            entities.append(('Process', match.group(1)))
            entities.append(('ProcessID', match.group(2)))

        # Usernames (after keywords)
        username_patterns = [
            r'\bfor\s+([a-z_][a-z0-9_-]*)\b',
            r'\buser\s+([a-z_][a-z0-9_-]*)\b',
            r'\bby\s+([a-z_][a-z0-9_-]*)\b',
            r'\bfrom\s+([a-z_][a-z0-9_-]*)@',
        ]
        excluded_usernames = {'root', 'unknown', 'invalid', 'port', 'from', 'to', 'on', 'at'}

        for pattern in username_patterns:
            for match in re.finditer(pattern, log_line, re.IGNORECASE):
                username = match.group(1).lower()
                if username not in excluded_usernames and len(username) > 1:
                    entities.append(('Username', match.group(1)))

        # System/Hostname (typically 4th token after datetime in syslog format)
        parts = log_line.split()
        if len(parts) > 3:
            potential_host = parts[3]
            # Remove any trailing colon
            potential_host = potential_host.rstrip(':')
            if re.match(r'^[a-zA-Z][a-zA-Z0-9-]*$', potential_host) and len(potential_host) > 2:
                entities.append(('System', potential_host))

        # Ports
        port_patterns = [
            r'\bport\s+(\d{1,5})\b',
            r':(\d{1,5})\b',
        ]
        for pattern in port_patterns:
            for match in re.finditer(pattern, log_line, re.IGNORECASE):
                port = match.group(1)
                if 1 <= int(port) <= 65535:
                    entities.append(('Port', port))

        return entities

    def extract_entities(self, log_line: str, use_hybrid: bool = True) -> List[Tuple[str, str]]:
        """
        HYBRID extraction: Model predictions + regex post-processing.

        Model handles: DNSName, DateTime, Error, Status (have I- tags)
        Regex handles: IPAddress, Process, Username, System (B- only, fragment)

        Args:
            log_line: Raw log entry text
            use_hybrid: If True, use hybrid extraction (recommended)

        Returns:
            List of (entity_type, entity_value) tuples

        Example:
            Input: "Jan 24 10:30:45 dnsmasq[1234]: query[A] example.com from 192.168.1.100"
            Output: [
                ('DateTime', 'Jan 24 10:30:45'),
                ('Process', 'dnsmasq'),
                ('ProcessID', '1234'),
                ('DNSName', 'example.com'),
                ('IPAddress', '192.168.1.100')
            ]
        """
        import torch

        if not self._is_loaded:
            raise RuntimeError('Model not loaded. Call load_model() first.')

        # Step 1: Tokenize with offset mapping
        inputs = self.tokenizer(
            log_line,
            return_tensors='pt',
            truncation=True,
            padding=True,
            return_offsets_mapping=True
        )

        offset_mapping = inputs.pop('offset_mapping')[0].tolist()

        # Move inputs to device
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        # Step 2: Model prediction
        with torch.no_grad():
            outputs = self.model(**inputs)
            predictions = torch.argmax(outputs.logits, dim=-1)

        pred_labels = [id2label[p.item()] for p in predictions[0]]

        # Step 3: Correct B-/I- tags
        pred_labels = self._correct_bio_tags(pred_labels)

        # Step 4: Extract model entities
        model_entities = self._extract_model_entities(log_line, pred_labels, offset_mapping)

        if not use_hybrid:
            return model_entities

        # Step 5: Hybrid post-processing
        # Keep model entities except for fragmented types
        entities = [e for e in model_entities if e[0] not in FRAGMENTED_ENTITY_TYPES]

        # Also remove DNSName from model (still fragments sometimes)
        entities = [e for e in entities if e[0] != 'DNSName']

        # Step 6: Add regex-extracted entities
        regex_entities = self._extract_regex_entities(log_line)
        entities.extend(regex_entities)

        # Deduplicate while preserving order
        seen = set()
        unique_entities = []
        for entity in entities:
            if entity not in seen:
                seen.add(entity)
                unique_entities.append(entity)

        return unique_entities

    def extract_entities_batch(
        self,
        log_lines: List[str],
        use_hybrid: bool = True,
        batch_size: int = 16
    ) -> List[List[Tuple[str, str]]]:
        """
        Extract entities from multiple log lines in batches.

        Args:
            log_lines: List of log entry texts
            use_hybrid: If True, use hybrid extraction
            batch_size: Number of logs to process at once

        Returns:
            List of entity lists, one per input log line
        """
        results = []

        for i in range(0, len(log_lines), batch_size):
            batch = log_lines[i:i + batch_size]
            for log_line in batch:
                entities = self.extract_entities(log_line, use_hybrid=use_hybrid)
                results.append(entities)

        return results


# ============================================================================
# FTE-HARM INTEGRATION UTILITIES
# ============================================================================

def entities_to_dict(entities: List[Tuple[str, str]]) -> Dict[str, List[str]]:
    """
    Convert entity list to dictionary format for FTE-HARM.
    Groups multiple instances of same entity type.

    Args:
        entities: List of (entity_type, value) tuples

    Returns:
        Dictionary mapping entity types to lists of values

    Example:
        Input: [('IPAddress', '192.168.1.1'), ('IPAddress', '10.0.0.1'), ('Process', 'sshd')]
        Output: {'IPAddress': ['192.168.1.1', '10.0.0.1'], 'Process': ['sshd']}
    """
    entity_dict: Dict[str, List[str]] = {}
    for entity_type, value in entities:
        if entity_type not in entity_dict:
            entity_dict[entity_type] = []
        entity_dict[entity_type].append(value)
    return entity_dict


def entities_to_tagged_string(entities: List[Tuple[str, str]]) -> str:
    """
    Convert entities to tagged string format.

    Args:
        entities: List of (entity_type, value) tuples

    Returns:
        Tagged string like "[DateTime: Jan 24] [Process: sshd] [IPAddress: 192.168.1.1]"
    """
    return ' '.join(f'[{entity_type}: {value}]' for entity_type, value in entities)


def format_for_fte_harm(
    log_line: str,
    entities: List[Tuple[str, str]]
) -> Dict[str, Any]:
    """
    Format extracted entities for FTE-HARM input.

    Args:
        log_line: Original log text
        entities: Extracted entities

    Returns:
        Dictionary formatted for FTE-HARM processing
    """
    return {
        'raw_log': log_line,
        'entities': entities_to_dict(entities),
        'entity_list': entities,
        'tagged_text': entities_to_tagged_string(entities),
    }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def quick_extract(log_line: str, model_name: str = 'distilroberta') -> List[Tuple[str, str]]:
    """
    Quick extraction function for single log lines.
    Loads model on first call (cached for subsequent calls).

    Args:
        log_line: Log text to extract from
        model_name: Model to use

    Returns:
        List of (entity_type, entity_value) tuples
    """
    # Use module-level cache
    global _cached_loader

    if '_cached_loader' not in globals() or _cached_loader is None or _cached_loader.model_name != model_name:
        _cached_loader = TransformerNERLoader(model_name)
        _cached_loader.load_model()

    return _cached_loader.extract_entities(log_line)


def get_available_models() -> Dict[str, str]:
    """
    Get dictionary of available models and their paths.

    Returns:
        Dictionary mapping model names to checkpoint paths
    """
    return TRANSFORMER_MODELS.copy()


def get_entity_labels() -> List[str]:
    """
    Get list of all 22 entity labels.

    Returns:
        List of entity label strings
    """
    return ENTITY_LABELS.copy()


def get_entity_types() -> List[str]:
    """
    Get list of entity types (without B-/I- prefixes).

    Returns:
        List of unique entity type names
    """
    types = set()
    for label in ENTITY_LABELS:
        if label != 'O':
            types.add(label[2:])  # Remove B- or I- prefix
    return sorted(types)


# ============================================================================
# MAIN / DEMO
# ============================================================================

if __name__ == '__main__':
    print('=' * 60)
    print('Transformer NER Loader for Forensic Log Entity Extraction')
    print('=' * 60)

    print('\nAvailable Models:')
    for name, path in TRANSFORMER_MODELS.items():
        print(f'  - {name}: {path}')

    print(f'\nEntity Labels ({len(ENTITY_LABELS)} total):')
    for i, label in enumerate(ENTITY_LABELS):
        print(f'  {i:2d}: {label}')

    print('\nEntity Types (unique):')
    for entity_type in get_entity_types():
        has_i_tag = entity_type in ENTITIES_WITH_I_TAG
        fragmented = entity_type in FRAGMENTED_ENTITY_TYPES
        status = ''
        if has_i_tag:
            status = '(has I- tag, spans tokens)'
        elif fragmented:
            status = '(no I- tag, uses regex)'
        print(f'  - {entity_type} {status}')

    print('\n' + '=' * 60)
    print('To use in Google Colab:')
    print('=' * 60)
    print('''
from transformer_ner_loader import TransformerNERLoader

# Initialize and load
loader = TransformerNERLoader('distilroberta')
loader.mount_google_drive()
loader.load_model()

# Extract entities
log = "Jan 24 10:30:45 server sshd[1234]: Failed login for admin from 192.168.1.100"
entities = loader.extract_entities(log)

for entity_type, value in entities:
    print(f"[{entity_type}] {value}")
''')
