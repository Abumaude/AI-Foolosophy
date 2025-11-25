"""
Dataset Loader and Ground Truth Pairing Module for FTE-HARM Validation

This module provides functionality to:
1. Scan forensic log dataset directories
2. Pair log files with their corresponding ground truth annotation files
3. Load and parse multiple ground truth formats
4. Validate dataset integrity
5. Generate dataset statistics
6. Iterate through matched log-ground truth pairs for FTE-HARM validation

Author: AI-Foolosophy Project
Purpose: Establish dataset integrity and ground truth correspondence for rigorous FTE-HARM validation
"""

import os
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum


# =============================================================================
# CONFIGURATION
# =============================================================================

class GroundTruthFormat(Enum):
    """Supported ground truth file formats"""
    LINE_BY_LINE = "line_by_line"  # Each line corresponds to same line in log
    CSV = "csv"                     # CSV with explicit line numbers
    JSON_TEMPORAL = "json_temporal"  # JSON with temporal attack windows
    UNKNOWN = "unknown"


@dataclass
class DatasetConfig:
    """Configuration for dataset paths and pairing rules"""
    # Default dataset paths (Google Colab paths)
    DATASET_PATHS: Dict[str, str] = field(default_factory=lambda: {
        'grp1': '/content/drive/My Drive/thesis/dataset/grp1',
        'grp2': '/content/drive/My Drive/thesis/dataset/grp2'
    })

    # File extensions for log files
    LOG_EXTENSIONS: List[str] = field(default_factory=lambda: ['.log', '.txt'])

    # Patterns that identify ground truth files
    LABEL_PATTERNS: List[str] = field(default_factory=lambda: [
        'label', 'labels', 'gt', 'ground_truth', 'annotation', 'truth'
    ])

    # Ground truth file extensions
    LABEL_EXTENSIONS: List[str] = field(default_factory=lambda: [
        '.log', '.csv', '.json', '.txt'
    ])


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class GroundTruthEntry:
    """Single ground truth entry for a log line"""
    label: str  # 'benign' or 'malicious'
    binary: int  # 0 or 1
    attack_type: str  # Classification (e.g., 'privilege_escalation')
    confidence: float = 1.0  # Ground truth confidence score
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_malicious(self) -> bool:
        """Check if entry is malicious"""
        return self.binary == 1 or self.label.lower() == 'malicious'


@dataclass
class AttackWindow:
    """Temporal attack window annotation"""
    start_time: str
    end_time: str
    attack_type: str
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DatasetPair:
    """Paired log file and ground truth file"""
    dataset_name: str
    log_file: str
    label_file: Optional[str]
    paired: bool
    base_path: str
    log_line_count: int = 0
    label_count: int = 0
    ground_truth_format: GroundTruthFormat = GroundTruthFormat.UNKNOWN

    def __str__(self) -> str:
        status = "PAIRED" if self.paired else "UNPAIRED"
        return f"[{status}] {self.dataset_name}: {os.path.basename(self.log_file)}"


@dataclass
class ValidationResult:
    """Result of dataset validation"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, error: str):
        self.valid = False
        self.errors.append(error)

    def add_warning(self, warning: str):
        self.warnings.append(warning)


@dataclass
class DatasetStatistics:
    """Statistics for a dataset or collection of datasets"""
    total_datasets: int = 0
    paired_datasets: int = 0
    unpaired_datasets: int = 0
    total_log_lines: int = 0
    total_malicious: int = 0
    total_benign: int = 0
    by_group: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_attack_type: Dict[str, int] = field(default_factory=dict)

    @property
    def malicious_ratio(self) -> float:
        """Ratio of malicious to total logs"""
        if self.total_log_lines == 0:
            return 0.0
        return self.total_malicious / self.total_log_lines

    @property
    def benign_ratio(self) -> float:
        """Ratio of benign to total logs"""
        if self.total_log_lines == 0:
            return 0.0
        return self.total_benign / self.total_log_lines


# =============================================================================
# DATASET SCANNER
# =============================================================================

class DatasetScanner:
    """
    Scans dataset directories to identify log files and ground truth files
    """

    def __init__(self, config: Optional[DatasetConfig] = None):
        self.config = config or DatasetConfig()

    def scan_directory(self, base_path: str) -> Dict[str, Dict[str, Any]]:
        """
        Scan directory for log files and identify structure

        Args:
            base_path: Path to dataset directory (grp1 or grp2)

        Returns:
            dict: Mapping of subdirectories to file lists
        """
        datasets = {}

        if not os.path.exists(base_path):
            print(f"Warning: Path does not exist: {base_path}")
            return datasets

        for root, dirs, files in os.walk(base_path):
            if files:
                subdir = os.path.relpath(root, base_path)
                if subdir == '.':
                    subdir = os.path.basename(base_path)

                log_files = self._identify_log_files(files)
                label_files = self._identify_label_files(files)

                if log_files or label_files:
                    datasets[subdir] = {
                        'path': root,
                        'log_files': log_files,
                        'label_files': label_files,
                        'all_files': files
                    }

        return datasets

    def scan_all_datasets(self, paths: Optional[Dict[str, str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Scan all configured dataset directories

        Args:
            paths: Optional dictionary of dataset paths to scan

        Returns:
            dict: Combined mapping of all datasets found
        """
        paths = paths or self.config.DATASET_PATHS
        all_datasets = {}

        for group_name, group_path in paths.items():
            print(f"Scanning {group_name}: {group_path}")
            group_datasets = self.scan_directory(group_path)

            # Prefix with group name to avoid collisions
            for subdir, info in group_datasets.items():
                key = f"{group_name}/{subdir}"
                all_datasets[key] = info

        return all_datasets

    def _identify_log_files(self, files: List[str]) -> List[str]:
        """Identify log files from a list of files"""
        log_files = []

        for f in files:
            # Skip files that look like labels
            if self._is_label_file(f):
                continue

            # Check extension
            _, ext = os.path.splitext(f)
            if ext.lower() in self.config.LOG_EXTENSIONS:
                # Additional check: should start with 'log' or not contain label patterns
                if f.startswith('log_') or not self._is_label_file(f):
                    log_files.append(f)

        return log_files

    def _identify_label_files(self, files: List[str]) -> List[str]:
        """Identify ground truth/label files from a list of files"""
        return [f for f in files if self._is_label_file(f)]

    def _is_label_file(self, filename: str) -> bool:
        """Check if a file is likely a ground truth/label file"""
        lower_name = filename.lower()

        for pattern in self.config.LABEL_PATTERNS:
            if pattern in lower_name:
                return True

        return False


# =============================================================================
# GROUND TRUTH PAIRING
# =============================================================================

class DatasetPairer:
    """
    Pairs log files with their corresponding ground truth files
    """

    def __init__(self, config: Optional[DatasetConfig] = None):
        self.config = config or DatasetConfig()

    def pair_log_with_groundtruth(
        self,
        log_file: str,
        label_files: List[str]
    ) -> Optional[str]:
        """
        Match a log file with its ground truth file

        Pairing rules (in priority order):
        1. Exact prefix match: log_X.log -> label_X.log
        2. Root name match with _labels suffix: X.log -> X_labels.csv
        3. Root name match with _gt suffix: X.log -> X_gt.txt
        4. Root name contained in label file

        Args:
            log_file: Name of log file
            label_files: List of potential label files

        Returns:
            str: Name of matched label file, or None if no match
        """
        if not label_files:
            return None

        # Extract root name from log file
        log_basename = os.path.basename(log_file)
        log_root = log_basename.replace('log_', '').replace('.log', '').replace('.txt', '')

        # Rule 1: Direct prefix match (log_X -> label_X)
        expected_label = log_basename.replace('log_', 'label_')
        if expected_label in label_files:
            return expected_label

        # Rule 2: Root name with _labels suffix
        for ext in ['.csv', '.log', '.txt', '.json']:
            expected = f"{log_root}_labels{ext}"
            if expected in label_files:
                return expected

        # Rule 3: Root name with _gt suffix
        for ext in ['.csv', '.log', '.txt', '.json']:
            expected = f"{log_root}_gt{ext}"
            if expected in label_files:
                return expected

        # Rule 4: Root name contained in label file
        for label_file in label_files:
            if log_root in label_file:
                return label_file

        # Rule 5: Try matching without underscores
        log_root_simple = log_root.replace('_', '')
        for label_file in label_files:
            label_simple = label_file.lower().replace('_', '')
            if log_root_simple in label_simple:
                return label_file

        return None

    def create_dataset_pairs(
        self,
        datasets: Dict[str, Dict[str, Any]]
    ) -> List[DatasetPair]:
        """
        Create complete pairing of all log files with ground truth

        Args:
            datasets: Output from DatasetScanner.scan_directory()

        Returns:
            list: List of DatasetPair objects
        """
        pairs = []

        for subdir, info in datasets.items():
            for log_file in info['log_files']:
                label_file = self.pair_log_with_groundtruth(
                    log_file,
                    info['label_files']
                )

                log_path = os.path.join(info['path'], log_file)
                label_path = os.path.join(info['path'], label_file) if label_file else None

                pair = DatasetPair(
                    dataset_name=subdir,
                    log_file=log_path,
                    label_file=label_path,
                    paired=label_file is not None,
                    base_path=info['path']
                )

                # Detect ground truth format
                if label_file:
                    pair.ground_truth_format = self._detect_format(label_file)

                pairs.append(pair)

        return pairs

    def _detect_format(self, label_file: str) -> GroundTruthFormat:
        """Detect the format of a ground truth file"""
        ext = os.path.splitext(label_file)[1].lower()

        if ext == '.csv':
            return GroundTruthFormat.CSV
        elif ext == '.json':
            return GroundTruthFormat.JSON_TEMPORAL
        elif ext in ['.log', '.txt']:
            return GroundTruthFormat.LINE_BY_LINE

        return GroundTruthFormat.UNKNOWN


# =============================================================================
# GROUND TRUTH LOADER
# =============================================================================

class GroundTruthLoader:
    """
    Loads and parses ground truth files in various formats
    """

    def load(
        self,
        label_file: str,
        format_hint: Optional[GroundTruthFormat] = None
    ) -> Union[List[GroundTruthEntry], Dict[int, GroundTruthEntry], Dict[str, Any]]:
        """
        Auto-detect format and load ground truth

        Args:
            label_file: Path to ground truth file
            format_hint: Optional format hint to override auto-detection

        Returns:
            Ground truth in appropriate format:
            - List[GroundTruthEntry] for line-by-line
            - Dict[int, GroundTruthEntry] for CSV with line numbers
            - Dict for JSON temporal
        """
        if not os.path.exists(label_file):
            raise FileNotFoundError(f"Ground truth file not found: {label_file}")

        # Auto-detect format if not provided
        if format_hint is None:
            ext = os.path.splitext(label_file)[1].lower()
            if ext == '.csv':
                format_hint = GroundTruthFormat.CSV
            elif ext == '.json':
                format_hint = GroundTruthFormat.JSON_TEMPORAL
            else:
                format_hint = GroundTruthFormat.LINE_BY_LINE

        # Load based on format
        if format_hint == GroundTruthFormat.CSV:
            return self._load_csv(label_file)
        elif format_hint == GroundTruthFormat.JSON_TEMPORAL:
            return self._load_json(label_file)
        else:
            return self._load_line_by_line(label_file)

    def _load_line_by_line(self, label_file: str) -> List[GroundTruthEntry]:
        """
        Load line-by-line ground truth (RussellMitchell format)

        Format: benign|malicious,0|1,attack_type

        Returns:
            list: Ground truth labels for each line
        """
        ground_truth = []

        with open(label_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                entry = self._parse_line_entry(line, line_num)
                ground_truth.append(entry)

        return ground_truth

    def _parse_line_entry(self, line: str, line_num: int) -> GroundTruthEntry:
        """Parse a single line-by-line entry"""
        parts = line.split(',')

        if len(parts) >= 3:
            return GroundTruthEntry(
                label=parts[0].strip(),
                binary=int(parts[1].strip()),
                attack_type=parts[2].strip(),
                metadata={'line_number': line_num}
            )
        elif len(parts) == 2:
            label = parts[0].strip()
            binary = int(parts[1].strip()) if parts[1].strip().isdigit() else (1 if label.lower() == 'malicious' else 0)
            return GroundTruthEntry(
                label=label,
                binary=binary,
                attack_type='unknown',
                metadata={'line_number': line_num}
            )
        else:
            # Single value - try to interpret
            label = parts[0].strip().lower()
            if label in ['0', '1']:
                binary = int(label)
                label = 'malicious' if binary == 1 else 'benign'
            else:
                binary = 1 if label == 'malicious' else 0

            return GroundTruthEntry(
                label=label,
                binary=binary,
                attack_type='unknown',
                metadata={'line_number': line_num}
            )

    def _load_csv(self, label_file: str) -> Dict[int, GroundTruthEntry]:
        """
        Load CSV ground truth with line numbers (Santos format)

        Returns:
            dict: Mapping line_number -> GroundTruthEntry
        """
        ground_truth = {}

        with open(label_file, 'r', encoding='utf-8', errors='ignore') as f:
            # Try to detect delimiter
            sample = f.read(1024)
            f.seek(0)

            delimiter = ','
            if '\t' in sample and ',' not in sample:
                delimiter = '\t'

            reader = csv.DictReader(f, delimiter=delimiter)

            for row in reader:
                # Find line number column (may have different names)
                line_num = None
                for key in ['line_number', 'line', 'line_num', 'lineno', 'idx', 'index']:
                    if key in row:
                        try:
                            line_num = int(row[key])
                            break
                        except (ValueError, TypeError):
                            continue

                if line_num is None:
                    continue

                # Extract label
                label = row.get('label', row.get('class', row.get('type', 'unknown')))

                # Extract binary
                binary_str = row.get('binary', row.get('malicious', row.get('is_attack', '0')))
                try:
                    binary = int(binary_str)
                except (ValueError, TypeError):
                    binary = 1 if label.lower() == 'malicious' else 0

                # Extract attack type
                attack_type = row.get('attack_type', row.get('attack', row.get('category', 'unknown')))

                # Extract confidence
                try:
                    confidence = float(row.get('confidence', row.get('score', 1.0)))
                except (ValueError, TypeError):
                    confidence = 1.0

                ground_truth[line_num] = GroundTruthEntry(
                    label=label,
                    binary=binary,
                    attack_type=attack_type,
                    confidence=confidence,
                    metadata={k: v for k, v in row.items()}
                )

        return ground_truth

    def _load_json(self, label_file: str) -> Dict[str, Any]:
        """
        Load JSON temporal ground truth

        Returns:
            dict: JSON structure with attack windows
        """
        with open(label_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Convert attack windows to AttackWindow objects if present
        if 'attack_windows' in data:
            windows = []
            for window in data['attack_windows']:
                windows.append(AttackWindow(
                    start_time=window.get('start_time', ''),
                    end_time=window.get('end_time', ''),
                    attack_type=window.get('attack_type', 'unknown'),
                    description=window.get('description', ''),
                    metadata={k: v for k, v in window.items()
                             if k not in ['start_time', 'end_time', 'attack_type', 'description']}
                ))
            data['attack_windows_parsed'] = windows

        return data


# =============================================================================
# DATASET VALIDATOR
# =============================================================================

class DatasetValidator:
    """
    Validates dataset integrity and pairing correctness
    """

    def __init__(self):
        self.loader = GroundTruthLoader()

    def validate_pair(self, pair: DatasetPair) -> ValidationResult:
        """
        Validate that log and ground truth files match correctly

        Checks:
        1. Files exist
        2. Line count matches (for line-by-line format)
        3. All referenced lines exist (for CSV format)
        4. Ground truth labels are valid

        Returns:
            ValidationResult: Validation results
        """
        result = ValidationResult(valid=True)

        # Check if log file exists
        if not os.path.exists(pair.log_file):
            result.add_error(f"Log file not found: {pair.log_file}")
            return result

        # If unpaired, that's a warning not an error
        if not pair.paired or pair.label_file is None:
            result.add_warning("No ground truth file paired with this log file")
            return result

        # Check if label file exists
        if not os.path.exists(pair.label_file):
            result.add_error(f"Label file not found: {pair.label_file}")
            return result

        # Count lines in log file
        log_lines = self._count_lines(pair.log_file)
        pair.log_line_count = log_lines

        # Load and validate ground truth
        try:
            ground_truth = self.loader.load(pair.label_file, pair.ground_truth_format)
        except Exception as e:
            result.add_error(f"Failed to load ground truth: {str(e)}")
            return result

        # Validate based on format
        if isinstance(ground_truth, list):
            # Line-by-line format
            gt_lines = len(ground_truth)
            pair.label_count = gt_lines

            if gt_lines != log_lines:
                result.add_error(
                    f"Line count mismatch: {log_lines} log lines, {gt_lines} labels"
                )

            # Validate labels
            self._validate_entries(ground_truth, result)

        elif isinstance(ground_truth, dict) and not 'attack_windows' in ground_truth:
            # CSV format with line numbers
            pair.label_count = len(ground_truth)

            if ground_truth:
                max_line = max(ground_truth.keys())

                if max_line > log_lines:
                    result.add_error(
                        f"Ground truth references line {max_line}, "
                        f"but log only has {log_lines} lines"
                    )

                # Check for gaps
                expected_lines = set(range(1, log_lines + 1))
                labeled_lines = set(ground_truth.keys())
                unlabeled = expected_lines - labeled_lines

                if unlabeled:
                    result.add_warning(
                        f"{len(unlabeled)} log lines have no ground truth label"
                    )

                # Validate labels
                self._validate_entries(list(ground_truth.values()), result)

        return result

    def validate_all(self, pairs: List[DatasetPair]) -> Dict[str, ValidationResult]:
        """
        Validate all dataset pairs

        Returns:
            dict: Mapping of dataset names to validation results
        """
        results = {}

        for pair in pairs:
            key = f"{pair.dataset_name}/{os.path.basename(pair.log_file)}"
            results[key] = self.validate_pair(pair)

        return results

    def _count_lines(self, filepath: str) -> int:
        """Count non-empty lines in a file"""
        count = 0
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    def _validate_entries(
        self,
        entries: List[GroundTruthEntry],
        result: ValidationResult
    ):
        """Validate ground truth entries"""
        valid_labels = {'benign', 'malicious', '0', '1', 'normal', 'attack', 'anomaly'}

        for i, entry in enumerate(entries):
            if entry.label.lower() not in valid_labels:
                result.add_warning(
                    f"Entry {i}: Unusual label '{entry.label}'"
                )

            if entry.binary not in [0, 1]:
                result.add_error(
                    f"Entry {i}: Invalid binary value {entry.binary}"
                )


# =============================================================================
# DATASET STATISTICS
# =============================================================================

class DatasetStatsGenerator:
    """
    Generates comprehensive dataset statistics
    """

    def __init__(self):
        self.loader = GroundTruthLoader()

    def generate_stats(self, pairs: List[DatasetPair]) -> DatasetStatistics:
        """
        Generate comprehensive dataset statistics

        Returns:
            DatasetStatistics: Dataset statistics
        """
        stats = DatasetStatistics()
        stats.total_datasets = len(pairs)
        stats.paired_datasets = sum(1 for p in pairs if p.paired)
        stats.unpaired_datasets = sum(1 for p in pairs if not p.paired)

        for pair in pairs:
            if not pair.paired or pair.label_file is None:
                continue

            # Initialize group stats
            group = pair.dataset_name
            if group not in stats.by_group:
                stats.by_group[group] = {
                    'total_logs': 0,
                    'total_malicious': 0,
                    'total_benign': 0,
                    'attack_types': {}
                }

            # Load ground truth
            try:
                ground_truth = self.loader.load(pair.label_file, pair.ground_truth_format)
            except Exception as e:
                print(f"Warning: Could not load {pair.label_file}: {e}")
                continue

            # Process based on format
            entries = self._get_entries(ground_truth)

            for entry in entries:
                stats.total_log_lines += 1
                stats.by_group[group]['total_logs'] += 1

                if entry.is_malicious:
                    stats.total_malicious += 1
                    stats.by_group[group]['total_malicious'] += 1

                    # Count by attack type
                    attack = entry.attack_type
                    stats.by_attack_type[attack] = stats.by_attack_type.get(attack, 0) + 1
                    stats.by_group[group]['attack_types'][attack] = \
                        stats.by_group[group]['attack_types'].get(attack, 0) + 1
                else:
                    stats.total_benign += 1
                    stats.by_group[group]['total_benign'] += 1

        return stats

    def _get_entries(
        self,
        ground_truth: Union[List, Dict]
    ) -> List[GroundTruthEntry]:
        """Extract entries from ground truth in any format"""
        if isinstance(ground_truth, list):
            return ground_truth
        elif isinstance(ground_truth, dict):
            if 'attack_windows' in ground_truth:
                # JSON temporal format - convert to entries
                return []  # Would need log file to map
            else:
                return list(ground_truth.values())
        return []

    def print_report(self, stats: DatasetStatistics):
        """Print formatted dataset report"""
        print("=" * 80)
        print("DATASET REPORT")
        print("=" * 80)
        print(f"Total datasets: {stats.total_datasets}")
        print(f"  Paired: {stats.paired_datasets}")
        print(f"  Unpaired: {stats.unpaired_datasets}")
        print()
        print(f"Total log lines: {stats.total_log_lines}")
        print(f"  Malicious: {stats.total_malicious} ({stats.malicious_ratio*100:.1f}%)")
        print(f"  Benign: {stats.total_benign} ({stats.benign_ratio*100:.1f}%)")
        print()

        if stats.by_group:
            print("By Group:")
            for group, info in stats.by_group.items():
                print(f"  {group}:")
                print(f"    Total logs: {info['total_logs']}")
                if info['total_logs'] > 0:
                    mal_ratio = info['total_malicious'] / info['total_logs'] * 100
                    ben_ratio = info['total_benign'] / info['total_logs'] * 100
                    print(f"    Malicious: {info['total_malicious']} ({mal_ratio:.1f}%)")
                    print(f"    Benign: {info['total_benign']} ({ben_ratio:.1f}%)")
            print()

        if stats.by_attack_type:
            print("By Attack Type:")
            sorted_attacks = sorted(
                stats.by_attack_type.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for attack, count in sorted_attacks:
                print(f"  {attack}: {count}")


# =============================================================================
# DATASET ITERATOR
# =============================================================================

class DatasetIterator:
    """
    Iterates through matched log-ground truth pairs for processing
    """

    def __init__(self):
        self.loader = GroundTruthLoader()

    def iterate_pairs(
        self,
        pairs: List[DatasetPair],
        process_fn: Optional[Callable] = None,
        verbose: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Iterate through all paired datasets and process each log entry

        Args:
            pairs: List of dataset pairs
            process_fn: Function to process each (log_line, ground_truth, line_num)
                       Returns any result to be collected
            verbose: Print progress information

        Returns:
            list: Results from processing
        """
        results = []

        for pair in pairs:
            if not pair.paired or pair.label_file is None:
                continue

            if verbose:
                print(f"Processing: {pair.dataset_name}")

            # Load log file
            with open(pair.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = [line.strip() for line in f if line.strip()]

            # Load ground truth
            try:
                ground_truth = self.loader.load(pair.label_file, pair.ground_truth_format)
            except Exception as e:
                if verbose:
                    print(f"  Warning: Could not load ground truth: {e}")
                continue

            # Process each log entry
            pair_results = self._process_entries(
                pair, log_lines, ground_truth, process_fn
            )
            results.extend(pair_results)

        return results

    def _process_entries(
        self,
        pair: DatasetPair,
        log_lines: List[str],
        ground_truth: Union[List, Dict],
        process_fn: Optional[Callable]
    ) -> List[Dict[str, Any]]:
        """Process entries based on ground truth format"""
        results = []

        if isinstance(ground_truth, list):
            # Line-by-line format
            for idx, (log_line, gt) in enumerate(zip(log_lines, ground_truth)):
                result = None
                if process_fn:
                    result = process_fn(log_line, gt, idx + 1)

                results.append({
                    'dataset': pair.dataset_name,
                    'line_number': idx + 1,
                    'log_line': log_line,
                    'ground_truth': gt,
                    'result': result
                })

        elif isinstance(ground_truth, dict) and 'attack_windows' not in ground_truth:
            # CSV format with line numbers
            for idx, log_line in enumerate(log_lines):
                line_num = idx + 1
                gt = ground_truth.get(
                    line_num,
                    GroundTruthEntry(
                        label='unknown',
                        binary=0,
                        attack_type='unknown'
                    )
                )

                result = None
                if process_fn:
                    result = process_fn(log_line, gt, line_num)

                results.append({
                    'dataset': pair.dataset_name,
                    'line_number': line_num,
                    'log_line': log_line,
                    'ground_truth': gt,
                    'result': result
                })

        return results


# =============================================================================
# FTE-HARM VALIDATION WORKFLOW
# =============================================================================

class FTEHARMValidator:
    """
    Validation workflow for FTE-HARM hypothesis testing
    """

    def __init__(self):
        self.iterator = DatasetIterator()

    def validate(
        self,
        pairs: List[DatasetPair],
        entity_extractor: Callable,
        hypothesis_scorer: Callable,
        hypothesis_configs: Dict[str, Any],
        triage_threshold: float = 0.45
    ) -> Dict[str, Any]:
        """
        Complete validation workflow for FTE-HARM

        Process:
        1. Load paired dataset
        2. Extract entities from log
        3. Score all hypotheses
        4. Determine triage decision
        5. Compare with ground truth
        6. Calculate metrics

        Args:
            pairs: Dataset pairs
            entity_extractor: Function to extract entities from log line
            hypothesis_scorer: Function to score hypotheses
            hypothesis_configs: FTE-HARM hypothesis configurations
            triage_threshold: Threshold for triage decision (default: 0.45 = LOW)

        Returns:
            dict: Validation metrics
        """
        validation_results = {
            'total': 0,
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0,
            'by_hypothesis': {},
            'by_attack_type': {},
            'predictions': []
        }

        def process_entry(log_line, gt, line_num):
            # Extract entities
            entities = entity_extractor(log_line)

            # Score all hypotheses
            hypothesis_scores = {}
            for hyp_name, hyp_config in hypothesis_configs.items():
                score_result = hypothesis_scorer(entities, hyp_config)
                hypothesis_scores[hyp_name] = score_result.get('p_score', 0.0)

            # Determine triage decision
            if hypothesis_scores:
                best_hypothesis = max(hypothesis_scores, key=hypothesis_scores.get)
                best_score = hypothesis_scores[best_hypothesis]
            else:
                best_hypothesis = None
                best_score = 0.0

            predicted_malicious = best_score >= triage_threshold
            actual_malicious = gt.is_malicious if isinstance(gt, GroundTruthEntry) else \
                               gt.get('binary', 0) == 1 or gt.get('label', '').lower() == 'malicious'

            return {
                'predicted': predicted_malicious,
                'actual': actual_malicious,
                'best_hypothesis': best_hypothesis,
                'best_score': best_score,
                'all_scores': hypothesis_scores,
                'attack_type': gt.attack_type if isinstance(gt, GroundTruthEntry) else gt.get('attack_type', 'unknown')
            }

        # Process all entries
        results = self.iterator.iterate_pairs(pairs, process_entry, verbose=True)

        # Aggregate metrics
        for entry in results:
            result = entry['result']
            if result is None:
                continue

            validation_results['total'] += 1
            validation_results['predictions'].append(result)

            predicted = result['predicted']
            actual = result['actual']

            if predicted and actual:
                validation_results['true_positives'] += 1
            elif predicted and not actual:
                validation_results['false_positives'] += 1
            elif not predicted and not actual:
                validation_results['true_negatives'] += 1
            else:
                validation_results['false_negatives'] += 1

            # Track by attack type
            attack_type = result['attack_type']
            if attack_type not in validation_results['by_attack_type']:
                validation_results['by_attack_type'][attack_type] = {
                    'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0
                }

            if predicted and actual:
                validation_results['by_attack_type'][attack_type]['tp'] += 1
            elif predicted and not actual:
                validation_results['by_attack_type'][attack_type]['fp'] += 1
            elif not predicted and not actual:
                validation_results['by_attack_type'][attack_type]['tn'] += 1
            else:
                validation_results['by_attack_type'][attack_type]['fn'] += 1

        # Calculate metrics
        self._calculate_metrics(validation_results)

        return validation_results

    def _calculate_metrics(self, results: Dict[str, Any]):
        """Calculate precision, recall, F1, accuracy"""
        tp = results['true_positives']
        fp = results['false_positives']
        tn = results['true_negatives']
        fn = results['false_negatives']

        results['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        results['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        if results['precision'] + results['recall'] > 0:
            results['f1_score'] = 2 * (results['precision'] * results['recall']) / \
                                  (results['precision'] + results['recall'])
        else:
            results['f1_score'] = 0.0

        results['accuracy'] = (tp + tn) / results['total'] if results['total'] > 0 else 0.0

        # Calculate metrics by attack type
        for attack_type, counts in results['by_attack_type'].items():
            tp = counts['tp']
            fp = counts['fp']
            tn = counts['tn']
            fn = counts['fn']

            counts['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            counts['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0.0

            if counts['precision'] + counts['recall'] > 0:
                counts['f1_score'] = 2 * (counts['precision'] * counts['recall']) / \
                                     (counts['precision'] + counts['recall'])
            else:
                counts['f1_score'] = 0.0

    def print_validation_report(self, results: Dict[str, Any]):
        """Print formatted validation report"""
        print("=" * 80)
        print("FTE-HARM VALIDATION REPORT")
        print("=" * 80)
        print()
        print("Overall Metrics:")
        print(f"  Total samples: {results['total']}")
        print(f"  True Positives: {results['true_positives']}")
        print(f"  False Positives: {results['false_positives']}")
        print(f"  True Negatives: {results['true_negatives']}")
        print(f"  False Negatives: {results['false_negatives']}")
        print()
        print(f"  Precision: {results['precision']:.4f}")
        print(f"  Recall: {results['recall']:.4f}")
        print(f"  F1 Score: {results['f1_score']:.4f}")
        print(f"  Accuracy: {results['accuracy']:.4f}")
        print()

        if results['by_attack_type']:
            print("By Attack Type:")
            for attack_type, metrics in results['by_attack_type'].items():
                total = metrics['tp'] + metrics['fp'] + metrics['tn'] + metrics['fn']
                print(f"  {attack_type} (n={total}):")
                print(f"    Precision: {metrics['precision']:.4f}")
                print(f"    Recall: {metrics['recall']:.4f}")
                print(f"    F1 Score: {metrics['f1_score']:.4f}")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def load_and_pair_datasets(
    paths: Optional[Dict[str, str]] = None,
    config: Optional[DatasetConfig] = None
) -> Tuple[List[DatasetPair], DatasetStatistics]:
    """
    Convenience function to load and pair all datasets

    Args:
        paths: Optional dictionary of dataset paths
        config: Optional DatasetConfig

    Returns:
        tuple: (list of DatasetPair, DatasetStatistics)
    """
    config = config or DatasetConfig()
    if paths:
        config.DATASET_PATHS = paths

    # Scan datasets
    scanner = DatasetScanner(config)
    datasets = scanner.scan_all_datasets()

    # Pair datasets
    pairer = DatasetPairer(config)
    pairs = pairer.create_dataset_pairs(datasets)

    # Generate statistics
    stats_gen = DatasetStatsGenerator()
    stats = stats_gen.generate_stats(pairs)

    return pairs, stats


def validate_datasets(pairs: List[DatasetPair]) -> Dict[str, ValidationResult]:
    """
    Convenience function to validate all dataset pairs

    Args:
        pairs: List of DatasetPair objects

    Returns:
        dict: Validation results by dataset
    """
    validator = DatasetValidator()
    return validator.validate_all(pairs)


def iterate_with_groundtruth(
    pairs: List[DatasetPair],
    process_fn: Callable
) -> List[Dict[str, Any]]:
    """
    Convenience function to iterate through datasets

    Args:
        pairs: List of DatasetPair objects
        process_fn: Function to process each entry

    Returns:
        list: Processing results
    """
    iterator = DatasetIterator()
    return iterator.iterate_pairs(pairs, process_fn)


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    # Example usage demonstrating the complete workflow

    print("Dataset Loader and Ground Truth Pairing Module")
    print("=" * 60)

    # Define custom paths for testing (replace with actual paths)
    test_paths = {
        'test': './test_datasets'
    }

    # Try to load datasets
    try:
        pairs, stats = load_and_pair_datasets(test_paths)

        print(f"\nFound {len(pairs)} dataset pairs")
        print(f"  Paired: {stats.paired_datasets}")
        print(f"  Unpaired: {stats.unpaired_datasets}")

        # Validate
        validation_results = validate_datasets(pairs)

        valid_count = sum(1 for r in validation_results.values() if r.valid)
        print(f"\nValidation: {valid_count}/{len(validation_results)} valid")

        # Print statistics
        stats_gen = DatasetStatsGenerator()
        stats_gen.print_report(stats)

    except Exception as e:
        print(f"Note: Could not load test datasets: {e}")
        print("This is expected if running outside of the Colab environment.")
        print("\nTo use this module, call load_and_pair_datasets() with your dataset paths.")
