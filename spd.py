#!/usr/bin/env python3

import argparse
import serial
import serial.tools.list_ports
import struct
import time
import logging
import os
import sys
import json
import mmap
import hashlib
import zlib
import tarfile
import zipfile
import shutil
import threading
import queue
import concurrent.futures
import tempfile
import re
import warnings
import io
import gzip
import lzma
import bz2
from typing import Optional, List, Dict, Tuple, Union, Callable, Any, Set
from enum import Enum, auto
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict, OrderedDict
from logging.handlers import RotatingFileHandler

# Optional dependencies with graceful degradation
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    warnings.warn("PyYAML not available - YAML batch files disabled")

try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False

try:
    import rarfile
    RARFILE_AVAILABLE = True
except ImportError:
    RARFILE_AVAILABLE = False

try:
    import lz4.frame
    LZ4_AVAILABLE = True
except ImportError:
    LZ4_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Metadata
__version__ = "3.0-pro"
__author__ = "SPDTool Community + Claude"
__license__ = "MIT"

# =============================================================================
# LOGGING SYSTEM (From Pro)
# =============================================================================

class JSONFormatter(logging.Formatter):
    """JSON format logger for machine parsing"""
    def format(self, record):
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'source': f"{record.filename}:{record.lineno}"
        }
        if hasattr(record, 'device_id'):
            log_data['device'] = record.device_id
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def setup_logging(level=logging.INFO, log_file: Optional[str] = None,
                  json_format: bool = False, max_bytes: int = 10*1024*1024,
                  backup_count: int = 5) -> logging.Logger:
    """Setup professional logging with rotation"""
    logger = logging.getLogger("SPDTool")
    logger.setLevel(level)
    logger.handlers = []

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)

    if json_format:
        console.setFormatter(JSONFormatter())
    else:
        console.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        ))

    logger.addHandler(console)

    # File handler with rotation
    if log_file:
        if json_format:
            file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes,
                                               backupCount=backup_count)
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes,
                                               backupCount=backup_count)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
        logger.addHandler(file_handler)

    return logger


logger = setup_logging()


# =============================================================================
# ENUMS & DATA STRUCTURES
# =============================================================================

class SPDCommands(Enum):
    """SPD BootROM Protocol Commands"""
    CMD_HANDSHAKE = 0xA0
    CMD_FDL1_LOAD = 0xA1
    CMD_FDL2_LOAD = 0xA2
    CMD_READ_FLASH = 0xB0
    CMD_WRITE_FLASH = 0xB1
    CMD_ERASE_FLASH = 0xB2
    CMD_GET_INFO = 0xB3
    CMD_GET_PARTITION_INFO = 0xB4
    CMD_READ_GPT = 0xB5
    CMD_GET_CHIP_ID = 0xB6
    CMD_SET_BAUDRATE = 0xB7
    CMD_RESET_DEVICE = 0xB8
    CMD_ACK = 0x5A
    CMD_NACK = 0xA5


class DeviceState(Enum):
    """Device state machine (from Pro)"""
    DISCONNECTED = auto()
    CONNECTED = auto()
    HANDSHAKE_DONE = auto()
    FDL1_LOADED = auto()
    FDL2_LOADED = auto()
    READY = auto()
    BUSY = auto()
    ERROR = auto()


class CompressionType(Enum):
    """Supported compression types"""
    NONE = "none"
    GZIP = "gz"
    LZMA = "xz"
    BZ2 = "bz2"
    LZ4 = "lz4"  # From Pro


class PACFormat(Enum):
    """Supported PAC formats"""
    ZIP = "zip"
    TAR = "tar"
    TAR_GZ = "tar.gz"
    TAR_BZ2 = "tar.bz2"
    TAR_XZ = "tar.xz"
    SEVENZ = "7z"
    RAR = "rar"
    SPD_CUSTOM = "spd"
    UNKNOWN = "unknown"


@dataclass
class DeviceProfile:
    """Device profile configuration"""
    name: str
    chip: str
    baudrate: int = 115200
    chunk_size: int = 0x4000
    timeout: float = 2.0
    fdl1_path: Optional[str] = None
    fdl2_path: Optional[str] = None
    pac_path: Optional[str] = None
    partitions: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'DeviceProfile':
        return cls(**data)


@dataclass
class PartitionInfo:
    """Enhanced partition metadata"""
    name: str
    address: int
    size: int
    is_critical: bool = False
    is_readonly: bool = False
    description: str = ""
    filesystem: str = "raw"
    backup_recommended: bool = True
    uuid: str = ""
    type_guid: str = ""

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'address': f"0x{self.address:08X}",
            'size': self.size,
            'size_mb': round(self.size / (1024*1024), 2),
            'is_critical': self.is_critical,
            'is_readonly': self.is_readonly,
            'description': self.description,
            'filesystem': self.filesystem,
            'backup_recommended': self.backup_recommended,
            'uuid': self.uuid
        }


@dataclass
class OperationJournal:
    """Resume-capable operation journal (from Pro)"""
    operation_id: str
    device_id: str
    operation_type: str
    start_time: str
    completed_chunks: Set[int] = field(default_factory=set)
    total_chunks: int = 0
    status: str = "running"
    metadata: Dict = field(default_factory=dict)

    def save(self, path: str):
        with open(path, 'w') as f:
            data = asdict(self)
            data['completed_chunks'] = list(data['completed_chunks'])
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'OperationJournal':
        with open(path, 'r') as f:
            data = json.load(f)
            data['completed_chunks'] = set(data.get('completed_chunks', []))
            return cls(**data)


# =============================================================================
# UTILITY CLASSES
# =============================================================================

class Checksum:
    """Checksum utilities (from Pro)"""

    ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'crc32': lambda: None  # Special handling
    }

    @classmethod
    def calculate(cls, filepath: str, algorithm: str = 'sha256') -> str:
        """Calculate file checksum"""
        if algorithm == 'crc32':
            crc = 0
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    crc = zlib.crc32(chunk, crc)
            return f"{crc & 0xffffffff:08x}"

        hasher = cls.ALGORITHMS[algorithm]()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def verify(cls, filepath: str, expected: str, algorithm: str = 'sha256') -> bool:
        """Verify file checksum"""
        actual = cls.calculate(filepath, algorithm)
        return actual.lower() == expected.lower()


class ArchiveExtractor:
    """Universal archive extractor (from Pro, enhanced)"""

    @staticmethod
    def detect_format(filepath: str) -> PACFormat:
        """Detect archive format"""
        path = Path(filepath)

        # Check extensions
        if path.suffix.lower() == '.zip' or zipfile.is_zipfile(filepath):
            return PACFormat.ZIP
        elif path.suffix.lower() == '.7z' and PY7ZR_AVAILABLE:
            return PACFormat.SEVENZ
        elif path.suffix.lower() == '.rar' and RARFILE_AVAILABLE:
            return PACFormat.RAR

        # Check tar variants
        if tarfile.is_tarfile(filepath):
            if '.tar.gz' in path.name.lower() or '.tgz' in path.name.lower():
                return PACFormat.TAR_GZ
            elif '.tar.bz2' in path.name.lower() or '.tbz2' in path.name.lower():
                return PACFormat.TAR_BZ2
            elif '.tar.xz' in path.name.lower() or '.txz' in path.name.lower():
                return PACFormat.TAR_XZ
            else:
                return PACFormat.TAR

        # Check SPD custom format
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
                if b'SPD' in header or b'PAC' in header:
                    return PACFormat.SPD_CUSTOM
        except:
            pass

        return PACFormat.UNKNOWN

    @staticmethod
    def extract(archive: str, output: str, pattern: Optional[str] = None) -> Dict[str, str]:
        """Extract archive and return file mappings"""
        fmt = ArchiveExtractor.detect_format(archive)
        logger.info(f"Extracting {fmt.value} archive: {archive}")

        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)

        extracted = {}

        try:
            if fmt == PACFormat.ZIP:
                extracted = ArchiveExtractor._extract_zip(archive, out_dir, pattern)
            elif fmt in (PACFormat.TAR, PACFormat.TAR_GZ, PACFormat.TAR_BZ2, PACFormat.TAR_XZ):
                extracted = ArchiveExtractor._extract_tar(archive, out_dir, pattern)
            elif fmt == PACFormat.SEVENZ and PY7ZR_AVAILABLE:
                extracted = ArchiveExtractor._extract_7z(archive, out_dir, pattern)
            elif fmt == PACFormat.RAR and RARFILE_AVAILABLE:
                extracted = ArchiveExtractor._extract_rar(archive, out_dir, pattern)
            elif fmt == PACFormat.SPD_CUSTOM:
                extracted = ArchiveExtractor._extract_spd(archive, out_dir, pattern)
            else:
                logger.error(f"Unsupported format: {fmt.value}")

            return extracted

        except Exception as e:
            logger.error(f"Extraction error: {e}")
            return {}

    @staticmethod
    def _extract_zip(archive: str, out: Path, pattern) -> Dict[str, str]:
        files = {}
        with zipfile.ZipFile(archive, 'r') as zf:
            for name in zf.namelist():
                if pattern and not re.search(pattern, name, re.I):
                    continue
                extract_path = out / Path(name).name
                with zf.open(name) as source, open(extract_path, 'wb') as target:
                    shutil.copyfileobj(source, target)

                basename = Path(name).name.lower()
                if 'fdl1' in basename:
                    files['fdl1'] = str(extract_path)
                elif 'fdl2' in basename:
                    files['fdl2'] = str(extract_path)
                else:
                    files[basename] = str(extract_path)

                logger.debug(f"Extracted: {basename}")
        return files

    @staticmethod
    def _extract_tar(archive: str, out: Path, pattern) -> Dict[str, str]:
        files = {}
        with tarfile.open(archive, 'r:*') as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if pattern and not re.search(pattern, member.name, re.I):
                    continue

                extract_path = out / Path(member.name).name
                with tf.extractfile(member) as source, open(extract_path, 'wb') as target:
                    shutil.copyfileobj(source, target)

                basename = Path(member.name).name.lower()
                if 'fdl1' in basename:
                    files['fdl1'] = str(extract_path)
                elif 'fdl2' in basename:
                    files['fdl2'] = str(extract_path)
                else:
                    files[basename] = str(extract_path)

                logger.debug(f"Extracted: {basename}")
        return files

    @staticmethod
    def _extract_7z(archive: str, out: Path, pattern) -> Dict[str, str]:
        files = {}
        with py7zr.SevenZipFile(archive, 'r') as zf:
            for name in zf.getnames():
                if pattern and not re.search(pattern, name, re.I):
                    continue
                zf.extract(out, [name])
                extract_path = out / Path(name).name

                basename = Path(name).name.lower()
                if 'fdl1' in basename:
                    files['fdl1'] = str(extract_path)
                elif 'fdl2' in basename:
                    files['fdl2'] = str(extract_path)
                else:
                    files[basename] = str(extract_path)

                logger.debug(f"Extracted: {basename}")
        return files

    @staticmethod
    def _extract_rar(archive: str, out: Path, pattern) -> Dict[str, str]:
        files = {}
        with rarfile.RarFile(archive, 'r') as rf:
            for name in rf.namelist():
                if pattern and not re.search(pattern, name, re.I):
                    continue
                rf.extract(name, out)
                extract_path = out / Path(name).name

                basename = Path(name).name.lower()
                if 'fdl1' in basename:
                    files['fdl1'] = str(extract_path)
                elif 'fdl2' in basename:
                    files['fdl2'] = str(extract_path)
                else:
                    files[basename] = str(extract_path)

                logger.debug(f"Extracted: {basename}")
        return files

    @staticmethod
    def _extract_spd(archive: str, out: Path, pattern) -> Dict[str, str]:
        """Extract SPD custom PAC format (simplified)"""
        files = {}
        try:
            with open(archive, 'rb') as f:
                # Read header
                header = f.read(1024)

                # Try to find FDL/image files (simplified extraction)
                offset = 1024
                file_count = 0

                while offset < os.path.getsize(archive):
                    f.seek(offset)
                    chunk = f.read(16)
                    if len(chunk) < 16:
                        break

                    # Look for file signatures
                    if chunk.startswith(b'\x7FELF') or chunk.startswith(b'MZ') or chunk.startswith(b'ANDROID!'):
                        file_name = f"extracted_{file_count}.bin"
                        f.seek(offset)
                        data = f.read(0x100000)  # Read up to 1MB

                        extract_path = out / file_name
                        with open(extract_path, 'wb') as out_file:
                            out_file.write(data)

                        files[file_name] = str(extract_path)
                        file_count += 1

                        offset += len(data)
                    else:
                        offset += 1024

            logger.info(f"Extracted {file_count} files from SPD PAC")
        except Exception as e:
            logger.error(f"SPD extraction error: {e}")

        return files


class CompressionHandler:
    """Handle compressed files with multiple algorithms"""

    @staticmethod
    def compress_file(input_file: str, output_file: str, compression: CompressionType) -> bool:
        """Compress a file"""
        try:
            logger.info(f"Compressing with {compression.value}...")

            with open(input_file, 'rb') as f_in:
                data = f_in.read()

            if compression == CompressionType.GZIP:
                with gzip.open(output_file, 'wb', compresslevel=9) as f_out:
                    f_out.write(data)
            elif compression == CompressionType.LZMA:
                with lzma.open(output_file, 'wb', preset=9) as f_out:
                    f_out.write(data)
            elif compression == CompressionType.BZ2:
                with bz2.open(output_file, 'wb', compresslevel=9) as f_out:
                    f_out.write(data)
            elif compression == CompressionType.LZ4 and LZ4_AVAILABLE:
                with lz4.frame.open(output_file, 'wb') as f_out:
                    f_out.write(data)
            else:
                with open(output_file, 'wb') as f_out:
                    f_out.write(data)

            orig_size = os.path.getsize(input_file)
            comp_size = os.path.getsize(output_file)
            ratio = (1 - comp_size / orig_size) * 100 if orig_size > 0 else 0

            logger.info(f"✓ Compressed: {orig_size} -> {comp_size} bytes ({ratio:.1f}% reduction)")
            return True

        except Exception as e:
            logger.error(f"Compression error: {e}")
            return False

    @staticmethod
    def decompress_file(input_file: str, output_file: str) -> bool:
        """Decompress a file (auto-detect)"""
        try:
            logger.info(f"Decompressing {input_file}...")

            data = None

            # Try each format
            for opener in [gzip.open, lzma.open, bz2.open]:
                try:
                    with opener(input_file, 'rb') as f:
                        data = f.read()
                    break
                except:
                    continue

            # Try LZ4 if available
            if data is None and LZ4_AVAILABLE:
                try:
                    with lz4.frame.open(input_file, 'rb') as f:
                        data = f.read()
                except:
                    pass

            # No compression
            if data is None:
                with open(input_file, 'rb') as f:
                    data = f.read()

            with open(output_file, 'wb') as f:
                f.write(data)

            logger.info(f"✓ Decompressed to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Decompression error: {e}")
            return False


class PartitionTableReader:
    """Read partition tables from device (GPT/MBR)"""

    GPT_HEADER_OFFSET = 0x200
    GPT_SIGNATURE = b"EFI PART"
    MBR_SIGNATURE = b"\x55\xAA"

    @staticmethod
    def read_gpt_table(data: bytes) -> Dict[str, PartitionInfo]:
        """Parse GPT partition table"""
        partitions = {}

        try:
            # Check GPT signature
            if data[PartitionTableReader.GPT_HEADER_OFFSET:PartitionTableReader.GPT_HEADER_OFFSET+8] != PartitionTableReader.GPT_SIGNATURE:
                logger.warning("Invalid GPT signature")
                return {}

            # Parse GPT header
            gpt_header = data[PartitionTableReader.GPT_HEADER_OFFSET:PartitionTableReader.GPT_HEADER_OFFSET+92]

            num_entries = struct.unpack("<I", gpt_header[80:84])[0]
            entry_size = struct.unpack("<I", gpt_header[84:88])[0]

            # Read partition entries (usually at LBA 2)
            entry_start = 0x400

            for i in range(min(num_entries, 128)):
                entry_offset = entry_start + (i * entry_size)
                entry = data[entry_offset:entry_offset+entry_size]

                # Check if entry is used
                if entry[:16] == b'\x00' * 16:
                    continue

                # Parse entry
                type_guid = entry[:16]
                unique_guid = entry[16:32]
                first_lba = struct.unpack("<Q", entry[32:40])[0]
                last_lba = struct.unpack("<Q", entry[40:48])[0]
                attributes = struct.unpack("<Q", entry[48:56])[0]

                # Get partition name (UTF-16LE)
                name_bytes = entry[56:128]
                try:
                    name = name_bytes.decode('utf-16le').rstrip('\x00')
                except:
                    name = f"partition_{i}"

                if name:
                    size = (last_lba - first_lba + 1) * 512

                    # Determine if critical based on common names
                    is_critical = name.lower() in {'bootloader', 'uboot', 'boot', 'recovery', 'gpt'}

                    part = PartitionInfo(
                        name=name.lower(),
                        address=first_lba * 512,
                        size=size,
                        is_critical=is_critical,
                        description=f'GPT partition (LBA {first_lba}-{last_lba})',
                        uuid=unique_guid.hex(),
                        type_guid=type_guid.hex()
                    )
                    partitions[name.lower()] = part

            logger.info(f"✓ Read {len(partitions)} partitions from GPT table")
            return partitions

        except Exception as e:
            logger.error(f"GPT parsing error: {e}")
            return {}

    @staticmethod
    def read_mbr_table(data: bytes) -> Dict[str, PartitionInfo]:
        """Parse MBR partition table"""
        partitions = {}

        try:
            # Check MBR signature
            if data[510:512] != PartitionTableReader.MBR_SIGNATURE:
                logger.warning("Invalid MBR signature")
                return {}

            # Parse 4 primary partitions
            for i in range(4):
                entry_offset = 446 + (i * 16)
                entry = data[entry_offset:entry_offset+16]

                # Check if partition exists
                if entry[4] == 0:
                    continue

                lba_start = struct.unpack("<I", entry[8:12])[0]
                num_sectors = struct.unpack("<I", entry[12:16])[0]

                if num_sectors > 0:
                    name = f"mbr_{i}"
                    part = PartitionInfo(
                        name=name,
                        address=lba_start * 512,
                        size=num_sectors * 512,
                        is_critical=False,
                        description=f'MBR partition {i} (type {entry[4]:02X})'
                    )
                    partitions[name] = part

            logger.info(f"✓ Read {len(partitions)} partitions from MBR table")
            return partitions

        except Exception as e:
            logger.error(f"MBR parsing error: {e}")
            return {}


class ConfigManager:
    """Manage configuration files and device profiles"""

    def __init__(self, config_path: str = ".spdtool.json"):
        self.config_path = Path.home() / config_path
        self.config: Dict = {}
        self.profiles: Dict[str, DeviceProfile] = {}
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)

                if 'profiles' in self.config:
                    for name, data in self.config['profiles'].items():
                        self.profiles[name] = DeviceProfile.from_dict(data)

                logger.debug(f"Loaded config from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")

    def save_config(self):
        """Save configuration to file"""
        try:
            self.config['profiles'] = {
                name: profile.to_dict()
                for name, profile in self.profiles.items()
            }

            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)

            logger.info(f"Config saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def add_profile(self, profile: DeviceProfile):
        """Add or update device profile"""
        self.profiles[profile.name] = profile
        self.save_config()

    def get_profile(self, name: str) -> Optional[DeviceProfile]:
        """Get device profile by name"""
        return self.profiles.get(name)

    def list_profiles(self) -> List[str]:
        """List all profile names"""
        return list(self.profiles.keys())


# =============================================================================
# SPD DEVICE CLASS (Combined best from both)
# =============================================================================

class SPDDevice:
    """Enhanced SPD device with best features from both versions"""

    CRITICAL_PARTS = {'bootloader', 'uboot', 'gpt', 'boot', 'recovery'}

    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0,
                 profile: Optional[DeviceProfile] = None, device_id: Optional[str] = None):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.serial_conn: Optional[serial.Serial] = None
        self.state = DeviceState.DISCONNECTED
        self.chunk_size = 0x4000
        self.partitions: Dict[str, PartitionInfo] = {}
        self.use_mmap = True
        self.profile = profile
        self.device_id = device_id or port
        self.logger = logging.getLogger(f"SPDTool.{self.device_id}")

        # Apply profile settings
        if profile:
            self.baudrate = profile.baudrate
            self.chunk_size = profile.chunk_size
            self.timeout = profile.timeout
            if profile.partitions:
                self._parse_profile_partitions(profile.partitions)

    def _parse_profile_partitions(self, data: Dict):
        """Parse partitions from profile"""
        for name, info in data.items():
            part = PartitionInfo(
                name=name,
                address=info.get('address', 0),
                size=info.get('size', 0),
                is_critical=info.get('is_critical', name in self.CRITICAL_PARTS),
                description=info.get('description', '')
            )
            self.partitions[name] = part

    def connect(self) -> bool:
        """Establish serial connection"""
        try:
            self.serial_conn = serial.Serial(
                self.port,
                self.baudrate,
                timeout=self.timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                write_timeout=5.0
            )
            time.sleep(0.5)
            self.state = DeviceState.CONNECTED
            self.logger.info(f"Connected to {self.port} at {self.baudrate} baud")
            return True
        except serial.SerialException as e:
            self.logger.error(f"Connection failed: {e}")
            self.state = DeviceState.ERROR
            return False

    def disconnect(self):
        """Disconnect serial port"""
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.close()
                self.state = DeviceState.DISCONNECTED
                self.logger.info("Disconnected")
            except Exception as e:
                self.logger.warning(f"Disconnect error: {e}")

    def send_command(self, command: int, data: bytes = b"", wait_response: bool = True,
                     response_timeout: float = 5.0) -> bytes:
        """Send command with proper framing"""
        if not self.serial_conn or not self.serial_conn.is_open:
            raise Exception("Not connected")

        try:
            length = 1 + len(data)
            header = struct.pack("<H", length)
            payload = bytes([command]) + data

            # Calculate checksum
            checksum = 0
            for b in payload:
                checksum ^= b

            packet = b"\x7E" + header + payload + bytes([checksum]) + b"\x7E"
            self.serial_conn.write(packet)
            self.serial_conn.flush()

            if not wait_response:
                return b""

            # Read response with timeout
            start_time = time.time()
            resp = b""
            while time.time() - start_time < response_timeout:
                if self.serial_conn.in_waiting:
                    resp += self.serial_conn.read(self.serial_conn.in_waiting)
                    if resp.startswith(b"\x7E") and resp.endswith(b"\x7E"):
                        return self._parse_response(resp)
                time.sleep(0.01)

            self.logger.warning(f"Command timeout after {response_timeout}s")
            return b""

        except Exception as e:
            self.logger.error(f"Send command error: {e}")
            return b""

    def _parse_response(self, response: bytes) -> bytes:
        """Parse response packet"""
        if not response.startswith(b"\x7E") or not response.endswith(b"\x7E"):
            self.logger.error("Invalid frame delimiters")
            return b""

        frame_data = response[1:-1]

        if len(frame_data) < 3:
            self.logger.error("Frame too short")
            return b""

        resp_len = struct.unpack("<H", frame_data[0:2])[0]
        expected_length = 2 + resp_len + 1

        if len(frame_data) != expected_length:
            self.logger.error(f"Length mismatch")
            return b""

        resp_payload = frame_data[2:2+resp_len]
        resp_chk = frame_data[2+resp_len]

        # Verify checksum
        calc_chk = 0
        for b in resp_payload:
            calc_chk ^= b

        if calc_chk != resp_chk:
            self.logger.error(f"Checksum mismatch")
            return b""

        return resp_payload

    def wait_for_ack(self, timeout: float = 5.0, retry: int = 3) -> bool:
        """Wait for ACK with retry"""
        for attempt in range(retry):
            resp = self.send_command(SPDCommands.CMD_ACK.value, wait_response=True,
                                     response_timeout=timeout)
            if resp and len(resp) > 0:
                if resp[0] == SPDCommands.CMD_ACK.value:
                    return True
                elif resp[0] == SPDCommands.CMD_NACK.value:
                    self.logger.warning(f"NACK (attempt {attempt + 1}/{retry})")
                else:
                    self.logger.debug(f"Unexpected response: {resp.hex()}")

            if attempt < retry - 1:
                time.sleep(0.5)

        self.logger.error("Failed to receive ACK")
        return False

    def handshake(self) -> bool:
        """Perform handshake"""
        self.logger.info("Performing handshake...")
        try:
            resp = self.send_command(SPDCommands.CMD_HANDSHAKE.value)

            if resp and len(resp) > 0:
                if resp[0] == SPDCommands.CMD_ACK.value:
                    self.state = DeviceState.HANDSHAKE_DONE
                    self.logger.info("✓ Handshake successful")
                    return True
                else:
                    self.logger.error(f"Handshake failed: unexpected response")
            else:
                self.logger.error("Handshake failed: no response")

            return False

        except Exception as e:
            self.logger.error(f"Handshake error: {e}")
            return False

    def load_fdl(self, fdl_path: str, stage: int) -> bool:
        """Load FDL bootloader stage"""
        self.logger.info(f"Loading FDL{stage}: {fdl_path}")

        if not os.path.exists(fdl_path):
            self.logger.error(f"FDL{stage} file not found")
            return False

        try:
            with open(fdl_path, 'rb') as f:
                fdl_data = f.read()

            file_size = len(fdl_data)
            self.logger.info(f"FDL{stage} size: {file_size} bytes")

            # Send load command
            cmd = SPDCommands.CMD_FDL1_LOAD if stage == 1 else SPDCommands.CMD_FDL2_LOAD
            cmd_data = struct.pack("<I", file_size)
            resp = self.send_command(cmd.value, cmd_data)

            if not resp or resp[0] != SPDCommands.CMD_ACK.value:
                self.logger.error(f"FDL{stage} load command rejected")
                return False

            # Send FDL data
            total_sent = 0
            start_time = time.time()

            # Use tqdm if available
            if TQDM_AVAILABLE:
                pbar = tqdm(total=file_size, unit='B', unit_scale=True, desc=f"FDL{stage}")
            else:
                pbar = None

            while total_sent < file_size:
                chunk_size = min(self.chunk_size, file_size - total_sent)
                chunk = fdl_data[total_sent:total_sent + chunk_size]

                self.serial_conn.write(chunk)
                self.serial_conn.flush()

                total_sent += chunk_size

                if pbar:
                    pbar.update(chunk_size)
                else:
                    progress = (total_sent / file_size) * 100
                    elapsed = time.time() - start_time
                    speed = total_sent / elapsed / 1024 if elapsed > 0 else 0
                    self.logger.info(f"Progress: {progress:.1f}% ({total_sent}/{file_size}) @ {speed:.1f} KB/s")

            if pbar:
                pbar.close()

            # Wait for ACK
            if not self.wait_for_ack():
                self.logger.error(f"FDL{stage} verification failed")
                return False

            if stage == 1:
                self.state = DeviceState.FDL1_LOADED
            else:
                self.state = DeviceState.FDL2_LOADED
                # After FDL2, device is ready
                self.state = DeviceState.READY

            self.logger.info(f"✓ FDL{stage} loaded successfully")
            return True

        except Exception as e:
            self.logger.error(f"FDL{stage} load error: {e}")
            return False

    def read_flash(self, address: int, length: int, output_file: str,
                   journal: Optional[OperationJournal] = None) -> bool:
        """Read flash with optional resume support"""
        self.logger.info(f"Reading flash: addr=0x{address:08X}, len=0x{length:08X}")

        if self.state != DeviceState.READY:
            self.logger.error("FDL2 must be loaded first")
            return False

        try:
            total_read = 0
            start_time = time.time()

            # Resume support
            if journal:
                total_chunks = journal.total_chunks
                completed = journal.completed_chunks
            else:
                total_chunks = (length + self.chunk_size - 1) // self.chunk_size
                completed = set()

            if TQDM_AVAILABLE:
                pbar = tqdm(total=length, unit='B', unit_scale=True, desc="Reading")
            else:
                pbar = None

            with open(output_file, 'wb') as f:
                chunk_idx = 0
                while total_read < length:
                    # Skip completed chunks
                    if journal and chunk_idx in completed:
                        chunk_size = min(self.chunk_size, length - total_read)
                        total_read += chunk_size
                        chunk_idx += 1
                        if pbar:
                            pbar.update(chunk_size)
                        continue

                    chunk_size = min(self.chunk_size, length - total_read)
                    current_addr = address + total_read

                    cmd_data = struct.pack("<II", current_addr, chunk_size)
                    resp = self.send_command(SPDCommands.CMD_READ_FLASH.value, cmd_data,
                                             response_timeout=10.0)

                    if not resp or len(resp) < chunk_size + 1:
                        self.logger.error(f"Read failed at offset 0x{total_read:08X}")
                        return False

                    data = resp[1:chunk_size + 1]
                    f.write(data)
                    total_read += len(data)

                    # Update journal
                    if journal:
                        journal.completed_chunks.add(chunk_idx)
                        journal.save(f"{output_file}.journal")

                    chunk_idx += 1

                    if pbar:
                        pbar.update(len(data))

            if pbar:
                pbar.close()

            # Remove journal on success
            if journal and os.path.exists(f"{output_file}.journal"):
                os.remove(f"{output_file}.journal")

            self.logger.info(f"✓ Flash read complete: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Flash read error: {e}")
            return False

    def write_flash(self, address: int, input_file: str, verify: bool = False,
                    journal: Optional[OperationJournal] = None) -> bool:
        """Write flash with verification and resume support"""
        self.logger.info(f"Writing flash: {input_file} -> addr=0x{address:08X}")

        if self.state != DeviceState.READY:
            self.logger.error("FDL2 must be loaded first")
            return False

        if not os.path.exists(input_file):
            self.logger.error(f"Input file not found: {input_file}")
            return False

        try:
            file_size = os.path.getsize(input_file)
            self.logger.info(f"File size: {file_size} bytes")

            total_written = 0
            start_time = time.time()

            # Resume support
            if journal:
                total_chunks = journal.total_chunks
                completed = journal.completed_chunks
            else:
                total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
                completed = set()

            if TQDM_AVAILABLE:
                pbar = tqdm(total=file_size, unit='B', unit_scale=True, desc="Writing")
            else:
                pbar = None

            with open(input_file, 'rb') as f:
                if self.use_mmap and file_size > self.chunk_size:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                        chunk_idx = 0
                        while total_written < file_size:
                            # Skip completed chunks
                            if journal and chunk_idx in completed:
                                chunk_size = min(self.chunk_size, file_size - total_written)
                                total_written += chunk_size
                                chunk_idx += 1
                                if pbar:
                                    pbar.update(chunk_size)
                                continue

                            chunk_size = min(self.chunk_size, file_size - total_written)
                            current_addr = address + total_written

                            chunk = mmapped[total_written:total_written + chunk_size]

                            cmd_data = struct.pack("<II", current_addr, chunk_size) + chunk
                            resp = self.send_command(SPDCommands.CMD_WRITE_FLASH.value, cmd_data,
                                                     response_timeout=10.0)

                            if not resp or resp[0] != SPDCommands.CMD_ACK.value:
                                self.logger.error(f"Write failed at offset 0x{total_written:08X}")
                                return False

                            total_written += chunk_size

                            # Update journal
                            if journal:
                                journal.completed_chunks.add(chunk_idx)
                                journal.save(f"{input_file}.journal")

                            chunk_idx += 1

                            if pbar:
                                pbar.update(chunk_size)
                else:
                    # For smaller files
                    data = f.read()
                    chunk_idx = 0
                    while total_written < file_size:
                        if journal and chunk_idx in completed:
                            chunk_size = min(self.chunk_size, file_size - total_written)
                            total_written += chunk_size
                            chunk_idx += 1
                            if pbar:
                                pbar.update(chunk_size)
                            continue

                        chunk_size = min(self.chunk_size, file_size - total_written)
                        current_addr = address + total_written

                        chunk = data[total_written:total_written + chunk_size]

                        cmd_data = struct.pack("<II", current_addr, chunk_size) + chunk
                        resp = self.send_command(SPDCommands.CMD_WRITE_FLASH.value, cmd_data,
                                                 response_timeout=10.0)

                        if not resp or resp[0] != SPDCommands.CMD_ACK.value:
                            self.logger.error(f"Write failed at offset 0x{total_written:08X}")
                            return False

                        total_written += chunk_size

                        if journal:
                            journal.completed_chunks.add(chunk_idx)
                            journal.save(f"{input_file}.journal")

                        chunk_idx += 1

                        if pbar:
                            pbar.update(chunk_size)

            if pbar:
                pbar.close()

            # Remove journal on success
            if journal and os.path.exists(f"{input_file}.journal"):
                os.remove(f"{input_file}.journal")

            # Verify if requested
            if verify:
                self.logger.info("Verifying write...")
                verify_file = input_file + ".verify"
                if self.read_flash(address, file_size, verify_file):
                    orig_hash = Checksum.calculate(input_file, 'sha256')
                    verify_hash = Checksum.calculate(verify_file, 'sha256')

                    os.remove(verify_file)

                    if orig_hash == verify_hash:
                        self.logger.info("✓ Verification passed")
                    else:
                        self.logger.error("✗ Verification failed: hash mismatch")
                        return False
                else:
                    self.logger.error("✗ Verification read failed")
                    return False

            self.logger.info(f"✓ Flash write complete")
            return True

        except Exception as e:
            self.logger.error(f"Flash write error: {e}")
            return False

    def erase_flash(self, address: int, length: int, secure: bool = False) -> bool:
        """Erase flash with optional secure erase"""
        self.logger.info(f"Erasing flash: addr=0x{address:08X}, len=0x{length:08X}")

        if self.state != DeviceState.READY:
            self.logger.error("FDL2 must be loaded first")
            return False

        try:
            cmd_data = struct.pack("<II", address, length)
            if secure:
                # DoD 5220.22-M: 3-pass overwrite
                self.logger.info("Secure erase enabled (3-pass)")
                cmd_data += b"\x01"

            resp = self.send_command(SPDCommands.CMD_ERASE_FLASH.value, cmd_data,
                                     response_timeout=60.0)

            if resp and resp[0] == SPDCommands.CMD_ACK.value:
                self.logger.info("✓ Flash erase complete")
                return True
            else:
                self.logger.error("Flash erase failed")
                return False

        except Exception as e:
            self.logger.error(f"Flash erase error: {e}")
            return False

    def read_partition_table_from_device(self) -> Dict[str, PartitionInfo]:
        """Read partition table from device"""
        self.logger.info("Reading partition table from device...")

        if self.state != DeviceState.READY:
            self.logger.warning("FDL2 not loaded, using common layout")
            return {}

        try:
            # Read first sectors containing GPT/MBR
            temp_file = tempfile.mktemp(suffix=".bin")

            if self.read_flash(0, 0x10000, temp_file):
                with open(temp_file, 'rb') as f:
                    data = f.read()

                # Try GPT first
                partitions = PartitionTableReader.read_gpt_table(data)

                # Fall back to MBR if GPT fails
                if not partitions:
                    partitions = PartitionTableReader.read_mbr_table(data)

                if os.path.exists(temp_file):
                    os.remove(temp_file)

                return partitions

            return {}

        except Exception as e:
            self.logger.error(f"Partition table read error: {e}")
            return {}

    def load_partitions(self, source: Union[str, Dict, None] = None) -> bool:
        """Load partition table from various sources"""
        if source is None:
            # Try device first
            device_parts = self.read_partition_table_from_device()

            if device_parts:
                self.partitions = device_parts
                self.logger.info(f"✓ Using device partition table ({len(device_parts)} partitions)")
                return True
            else:
                # Fall back to common layout
                self._load_common_partitions()
                self.logger.warning("Using common partition layout (fallback)")
                return True

        elif isinstance(source, str) and os.path.exists(source):
            with open(source, 'r') as f:
                self._parse_profile_partitions(json.load(f))
        elif isinstance(source, dict):
            self._parse_profile_partitions(source)

        return len(self.partitions) > 0

    def _load_common_partitions(self):
        """Load common SPD partition layout"""
        common = {
            'gpt': {'address': 0x0, 'size': 0x40000, 'is_critical': True, 'description': 'Partition table'},
            'bootloader': {'address': 0x40000, 'size': 0x80000, 'is_critical': True, 'description': 'Bootloader'},
            'uboot': {'address': 0xC0000, 'size': 0x40000, 'is_critical': True, 'description': 'U-Boot'},
            'boot': {'address': 0x100000, 'size': 0x400000, 'is_critical': True, 'description': 'Kernel/ramdisk'},
            'recovery': {'address': 0x500000, 'size': 0x400000, 'is_critical': True, 'description': 'Recovery'},
            'system': {'address': 0x900000, 'size': 0x6000000, 'is_critical': False, 'description': 'Android system'},
            'vendor': {'address': 0x6900000, 'size': 0x2000000, 'is_critical': False, 'description': 'Vendor files'},
            'userdata': {'address': 0x8900000, 'size': 0x10000000, 'is_critical': False, 'description': 'User data'},
            'cache': {'address': 0x18900000, 'size': 0x4000000, 'is_critical': False, 'description': 'Cache'},
            'modem': {'address': 0x1E200000, 'size': 0x4000000, 'is_critical': False, 'description': 'Modem firmware'},
            'persist': {'address': 0x1D180000, 'size': 0x800000, 'is_critical': False, 'description': 'Persistent data'},
        }
        self._parse_profile_partitions(common)

    def _check_partition_critical(self, partition_name: str, force: bool = False) -> bool:
        """Check if partition is critical"""
        if partition_name not in self.partitions:
            return True

        part = self.partitions[partition_name]

        if part.is_critical and not force:
            self.logger.error(f"⚠ '{partition_name}' is CRITICAL! Use --force to proceed")
            return False

        if part.is_critical and force:
            self.logger.warning(f"⚠ FORCING operation on critical partition '{partition_name}'")

        return True

    def read_partition(self, name: str, output: str, compress: bool = False,
                       compression_type: CompressionType = CompressionType.GZIP) -> bool:
        """Read partition with optional compression"""
        if name not in self.partitions:
            self.logger.error(f"Unknown partition: {name}")
            return False

        part = self.partitions[name]

        if compress:
            tmp = output + '.tmp'
            if not self.read_flash(part.address, part.size, tmp):
                return False

            compressed = output + '.' + compression_type.value
            if CompressionHandler.compress_file(tmp, compressed, compression_type):
                os.remove(tmp)
                return True
            else:
                self.logger.warning("Compression failed, keeping uncompressed")
                shutil.move(tmp, output)
                return True

        return self.read_flash(part.address, part.size, output)

    def write_partition(self, name: str, input_file: str, verify: bool = False,
                        force: bool = False) -> bool:
        """Write to partition"""
        if name not in self.partitions:
            self.logger.error(f"Unknown partition: {name}")
            return False

        if not self._check_partition_critical(name, force):
            return False

        part = self.partitions[name]
        return self.write_flash(part.address, input_file, verify)

    def erase_partition(self, name: str, force: bool = False, secure: bool = False) -> bool:
        """Erase partition"""
        if name not in self.partitions:
            self.logger.error(f"Unknown partition: {name}")
            return False

        if not self._check_partition_critical(name, force):
            return False

        part = self.partitions[name]
        return self.erase_flash(part.address, part.size, secure)

    def backup_partition(self, name: str, backup_dir: str = "backups",
                         compression: CompressionType = CompressionType.NONE) -> Optional[str]:
        """Backup partition with timestamp"""
        if name not in self.partitions:
            self.logger.error(f"Unknown partition: {name}")
            return None

        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_file = os.path.join(backup_dir, f"{name}_{timestamp}.img")

        compress = compression != CompressionType.NONE

        if self.read_partition(name, base_file, compress, compression):
            if compress:
                return base_file + '.' + compression.value
            return base_file

        return None

    def get_device_info(self) -> Dict:
        """Get device information"""
        try:
            resp = self.send_command(SPDCommands.CMD_GET_INFO.value, response_timeout=2.0)

            info = {
                'port': self.port,
                'baudrate': self.baudrate,
                'state': self.state.name,
                'partitions_loaded': len(self.partitions),
            }

            if resp and len(resp) > 0:
                info['raw_response'] = resp.hex()

            return info

        except Exception as e:
            self.logger.error(f"Get device info error: {e}")
            return {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.disconnect()


# =============================================================================
# MULTI-DEVICE MANAGER (From Pro)
# =============================================================================

class MultiDeviceManager:
    """Manage multiple devices in parallel"""

    def __init__(self, max_workers: int = 8):
        self.devices: Dict[str, SPDDevice] = {}
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.results: List[Dict] = []

    def scan_ports(self, pattern: Optional[str] = None) -> List[str]:
        """Scan for SPD devices"""
        ports = []
        for port in serial.tools.list_ports.comports():
            if pattern and not re.search(pattern, port.device):
                continue
            if any(x in port.description.lower() for x in ['spd', 'spreadtrum', 'unisoc', 'sprd', 'diag']):
                ports.append(port.device)
        return ports

    def add_device(self, port: str, **kwargs) -> Optional[SPDDevice]:
        """Add device to manager"""
        device = SPDDevice(port, device_id=port, **kwargs)
        if device.connect():
            self.devices[port] = device
            return device
        return None

    def execute_parallel(self, operation: Callable, *args, **kwargs) -> List[Dict]:
        """Execute operation on all devices in parallel"""
        futures = []

        for port, device in self.devices.items():
            future = self.executor.submit(operation, device, *args, **kwargs)
            futures.append((port, future))

        results = []
        for port, future in futures:
            try:
                result = future.result(timeout=300)
                results.append({'port': port, 'success': result, 'error': None})
            except Exception as e:
                results.append({'port': port, 'success': False, 'error': str(e)})

        return results

    def disconnect_all(self):
        """Disconnect all devices"""
        for device in self.devices.values():
            device.disconnect()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.disconnect_all()
        self.executor.shutdown()


# =============================================================================
# BATCH PROCESSOR (Enhanced from both)
# =============================================================================

class BatchProcessor:
    """Process batch operations from YAML/JSON files"""

    @staticmethod
    def load_batch_file(filepath: str) -> List[Dict]:
        """Load batch operations from file"""
        ext = Path(filepath).suffix.lower()

        if ext in ['.yaml', '.yml'] and YAML_AVAILABLE:
            with open(filepath, 'r') as f:
                return yaml.safe_load(f)
        elif ext == '.json':
            with open(filepath, 'r') as f:
                return json.load(f)
        else:
            raise ValueError(f"Unsupported batch file format: {ext}")

    @staticmethod
    def execute(device: SPDDevice, batch_file: str, force: bool = False) -> bool:
        """Execute batch operations"""
        logger.info(f"Loading batch file: {batch_file}")

        try:
            operations = BatchProcessor.load_batch_file(batch_file)

            if not isinstance(operations, list):
                logger.error("Batch file must contain a list of operations")
                return False

            logger.info(f"Executing {len(operations)} operations...")

            for i, op in enumerate(operations):
                logger.info(f"Operation {i+1}/{len(operations)}: {op.get('type', 'unknown')}")

                op_type = op.get('type')
                success = False

                if op_type == 'read':
                    success = device.read_flash(op['address'], op['length'], op['output'])
                elif op_type == 'write':
                    success = device.write_flash(op['address'], op['input'], op.get('verify', False))
                elif op_type == 'erase':
                    success = device.erase_flash(op['address'], op['length'], op.get('secure', False))
                elif op_type == 'readpart':
                    compress_type = CompressionType(op.get('compression', 'none'))
                    success = device.read_partition(op['partition'], op['output'],
                                                     compress=(compress_type != CompressionType.NONE),
                                                     compression_type=compress_type)
                elif op_type == 'writepart':
                    success = device.write_partition(op['partition'], op['input'],
                                                      op.get('verify', False), force)
                elif op_type == 'erasepart':
                    success = device.erase_partition(op['partition'], force, op.get('secure', False))
                elif op_type == 'backup':
                    compress_type = CompressionType(op.get('compression', 'none'))
                    result = device.backup_partition(op['partition'], op.get('backup_dir', 'backups'),
                                                      compress_type)
                    success = result is not None
                else:
                    logger.error(f"Unknown operation type: {op_type}")
                    success = False

                if not success:
                    logger.error(f"Operation {i+1} failed")
                    return False

            logger.info("✓ All batch operations completed successfully")
            return True

        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            return False


# =============================================================================
# MAIN CLI
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description=f"SPDTool V3 Pro v{__version__} - Ultimate Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic operations (backward compatible)
  python spdtool.py /dev/ttyUSB0 handshake
  python spdtool.py /dev/ttyUSB0 readpart boot boot.img --fdl1 fdl1.bin --fdl2 fdl2.bin

  # Multi-device parallel
  python spdtool.py multi --scan ota firmware.zip

  # Batch operations
  python spdtool.py /dev/ttyUSB0 batch --batch-file ops.yaml

  # With compression
  python spdtool.py /dev/ttyUSB0 backup system --compress lz4

  # Device profiles
  python spdtool.py profile create my_device --chip SC9863A --pac firmware.pac
  python spdtool.py /dev/ttyUSB0 backup boot --profile my_device

  # Resume interrupted operation
  python spdtool.py /dev/ttyUSB0 write 0x100000 large.bin --resume
        """
    )

    parser.add_argument("port", nargs="?", help="Serial port, 'multi', or 'profile'")
    parser.add_argument("command", nargs="?", choices=[
        "handshake", "loadfdl1", "loadfdl2", "read", "write", "erase",
        "readpart", "writepart", "erasepart", "backup", "listparts", "info",
        "extractpac", "batch", "ota", "profile", "scan"
    ])
    parser.add_argument("args", nargs="*", help="Command arguments")

    # Connection
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--timeout", type=float, default=2.0, help="Serial timeout")
    parser.add_argument("--scan", action="store_true", help="Auto-scan for devices")

    # FDL/PAC
    parser.add_argument("--fdl1", help="FDL1 path")
    parser.add_argument("--fdl2", help="FDL2 path")
    parser.add_argument("--pac", help="PAC/OTA file")

    # Operations
    parser.add_argument("--verify", action="store_true", help="Verify writes")
    parser.add_argument("--force", action="store_true", help="Force critical operations")
    parser.add_argument("--secure-erase", action="store_true", help="3-pass secure erase")
    parser.add_argument("--resume", action="store_true", help="Resume interrupted operation")

    # Compression
    parser.add_argument("--compress", choices=['none', 'gz', 'xz', 'bz2', 'lz4'],
                        default='none', help="Compression type")

    # Profile
    parser.add_argument("--profile", help="Device profile name")
    parser.add_argument("--chip", help="Chip name for profile creation")

    # Performance
    parser.add_argument("--no-mmap", action="store_true", help="Disable mmap")
    parser.add_argument("--chunk-size", type=int, default=0x4000, help="Chunk size")
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers")

    # Logging
    parser.add_argument("--log", help="Log file path")
    parser.add_argument("--json-log", action="store_true", help="JSON format logging")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")

    # Batch
    parser.add_argument("--batch-file", help="Batch operations file (YAML/JSON)")

    # Checksum
    parser.add_argument("--checksum", choices=['md5', 'sha1', 'sha256', 'crc32'],
                        help="Verify file checksum")
    parser.add_argument("--expected-hash", help="Expected checksum value")

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.debug else (logging.WARNING if args.quiet else logging.INFO)
    global logger
    logger = setup_logging(log_level, args.log, args.json_log)

    # Initialize config manager
    config = ConfigManager()

    # Handle profile commands
    if args.port == "profile" or args.command == "profile":
        if not args.args:
            parser.error("Profile subcommand required: create, list, show, delete")

        subcommand = args.args[0]

        if subcommand == "list":
            profiles = config.list_profiles()
            if profiles:
                print("\nAvailable device profiles:")
                print("-" * 60)
                for name in profiles:
                    profile = config.get_profile(name)
                    print(f"  {name:<20} Chip: {profile.chip}")
                print("-" * 60)
            else:
                print("No device profiles configured")
            return

        elif subcommand == "create":
            if len(args.args) < 2:
                parser.error("Profile name required")

            profile_name = args.args[1]

            if not args.chip:
                parser.error("--chip required for profile creation")

            profile = DeviceProfile(
                name=profile_name,
                chip=args.chip,
                baudrate=args.baud,
                chunk_size=args.chunk_size,
                timeout=args.timeout,
                fdl1_path=args.fdl1,
                fdl2_path=args.fdl2,
                pac_path=args.pac
            )

            config.add_profile(profile)
            print(f"✓ Profile '{profile_name}' created")
            return

        elif subcommand == "show":
            if len(args.args) < 2:
                parser.error("Profile name required")

            profile = config.get_profile(args.args[1])
            if profile:
                print(json.dumps(profile.to_dict(), indent=2))
            else:
                print(f"Profile '{args.args[1]}' not found")
            return

        elif subcommand == "delete":
            if len(args.args) < 2:
                parser.error("Profile name required")

            profile_name = args.args[1]
            if profile_name in config.profiles:
                del config.profiles[profile_name]
                config.save_config()
                print(f"✓ Profile '{profile_name}' deleted")
            else:
                print(f"Profile '{profile_name}' not found")
            return

    # Handle listparts without device
    if args.command == "listparts" and not args.port:
        device = SPDDevice("dummy")
        device._load_common_partitions()
        print("\n" + "="*90)
        print("Common SPD Partition Layout")
        print("="*90)
        print(f"{'Name':<15} {'Address':<12} {'Size':<12} {'Critical':<10} {'Description'}")
        print("-"*90)
        for name, part in sorted(device.partitions.items()):
            size_mb = part.size / (1024*1024)
            critical = "⚠ YES" if part.is_critical else "No"
            print(f"{name:<15} 0x{part.address:08X}   {size_mb:6.1f} MB    {critical:<10} {part.description}")
        print("="*90)
        return

    # Handle PAC extraction
    if args.command == "extractpac":
        if not args.args:
            parser.error("PAC file required")

        pac_file = args.args[0]
        output_dir = args.args[1] if len(args.args) > 1 else None

        extracted = ArchiveExtractor.extract(pac_file, output_dir or f"{pac_file}_extracted")

        if extracted:
            print(f"\n✓ Extracted files:")
            for key, path in extracted.items():
                print(f"  {key}: {path}")
        sys.exit(0 if extracted else 1)

    # Handle multi-device operations
    if args.port == "multi" or args.scan:
        manager = MultiDeviceManager(max_workers=args.workers)

        if args.scan:
            ports = manager.scan_ports()
            print(f"\nFound {len(ports)} SPD devices:")
            for port in ports:
                print(f"  - {port}")

            if not ports:
                print("No SPD devices found")
                return

            # Connect to all
            for port in ports:
                manager.add_device(port, baudrate=args.baud, timeout=args.timeout)

        logger.info(f"Managing {len(manager.devices)} devices")

        # TODO: Implement multi-device operations
        logger.warning("Multi-device operations not fully implemented yet")

        manager.disconnect_all()
        return

    # Single device operations
    if not args.port:
        parser.error("Port required for this command")

    # Load profile if specified
    profile = None
    if args.profile:
        profile = config.get_profile(args.profile)
        if not profile:
            logger.error(f"Profile '{args.profile}' not found")
            sys.exit(1)
        logger.info(f"Using profile: {args.profile}")

    # Create device
    device = SPDDevice(args.port, args.baud, args.timeout, profile)
    device.chunk_size = args.chunk_size
    device.use_mmap = not args.no_mmap

    success = False

    try:
        # Connect
        if not device.connect():
            logger.error("Failed to connect")
            sys.exit(1)

        # Auto-extract PAC if provided
        if args.pac:
            logger.info(f"Extracting PAC: {args.pac}")
            extracted = ArchiveExtractor.extract(args.pac, f"{args.pac}_extracted")

            if extracted:
                if 'fdl1' in extracted and not args.fdl1:
                    args.fdl1 = extracted['fdl1']
                if 'fdl2' in extracted and not args.fdl2:
                    args.fdl2 = extracted['fdl2']

        # Use profile FDLs if not overridden
        if profile:
            if not args.fdl1 and profile.fdl1_path:
                args.fdl1 = profile.fdl1_path
            if not args.fdl2 and profile.fdl2_path:
                args.fdl2 = profile.fdl2_path

        # Load FDLs for relevant commands
        if args.command in ["readpart", "writepart", "erasepart", "backup", "read", "write", "erase", "ota"]:
            if args.fdl1:
                if not device.load_fdl(args.fdl1, 1):
                    sys.exit(1)
            if args.fdl2:
                if not device.load_fdl(args.fdl2, 2):
                    sys.exit(1)

        # Execute command
        if args.command == "handshake":
            success = device.handshake()

        elif args.command == "loadfdl1":
            path = args.args[0] if args.args else args.fdl1
            if path:
                success = device.load_fdl(path, 1)
            else:
                parser.error("FDL1 path required")

        elif args.command == "loadfdl2":
            path = args.args[0] if args.args else args.fdl2
            if path:
                success = device.load_fdl(path, 2)
            else:
                parser.error("FDL2 path required")

        elif args.command == "read":
            if len(args.args) < 3:
                parser.error("Usage: read <addr> <len> <file>")
            addr = int(args.args[0], 0)
            length = int(args.args[1], 0)

            # Resume support
            journal = None
            journal_file = args.args[2] + ".journal"
            if args.resume and os.path.exists(journal_file):
                journal = OperationJournal.load(journal_file)
                logger.info(f"Resuming operation: {len(journal.completed_chunks)}/{journal.total_chunks} chunks")

            success = device.read_flash(addr, length, args.args[2], journal)

        elif args.command == "write":
            if len(args.args) < 2:
                parser.error("Usage: write <addr> <file>")
            addr = int(args.args[0], 0)

            # Resume support
            journal = None
            journal_file = args.args[1] + ".journal"
            if args.resume and os.path.exists(journal_file):
                journal = OperationJournal.load(journal_file)
                logger.info(f"Resuming operation: {len(journal.completed_chunks)}/{journal.total_chunks} chunks")

            success = device.write_flash(addr, args.args[1], args.verify, journal)

        elif args.command == "erase":
            if len(args.args) < 2:
                parser.error("Usage: erase <addr> <len>")
            addr = int(args.args[0], 0)
            length = int(args.args[1], 0)
            success = device.erase_flash(addr, length, args.secure_erase)

        elif args.command == "readpart":
            if len(args.args) < 2:
                parser.error("Usage: readpart <partition> <file>")
            device.load_partitions()
            compress_type = CompressionType(args.compress)
            success = device.read_partition(args.args[0], args.args[1],
                                            compress=(compress_type != CompressionType.NONE),
                                            compression_type=compress_type)

        elif args.command == "writepart":
            if len(args.args) < 2:
                parser.error("Usage: writepart <partition> <file>")
            device.load_partitions()
            success = device.write_partition(args.args[0], args.args[1], args.verify, args.force)

        elif args.command == "erasepart":
            if len(args.args) < 1:
                parser.error("Usage: erasepart <partition>")
            device.load_partitions()
            success = device.erase_partition(args.args[0], args.force, args.secure_erase)

        elif args.command == "backup":
            if len(args.args) < 1:
                parser.error("Usage: backup <partition> [dir]")
            device.load_partitions()
            backup_dir = args.args[1] if len(args.args) > 1 else "backups"
            compress_type = CompressionType(args.compress)
            result = device.backup_partition(args.args[0], backup_dir, compress_type)
            if result:
                logger.info(f"Backup saved: {result}")
                success = True

        elif args.command == "listparts":
            device.load_partitions()
            print("\n" + "="*90)
            print("Device Partitions")
            print("="*90)
            print(f"{'Name':<15} {'Address':<12} {'Size':<12} {'Critical':<10} {'Description'}")
            print("-"*90)
            for name, part in sorted(device.partitions.items()):
                size_mb = part.size / (1024*1024)
                critical = "⚠ YES" if part.is_critical else "No"
                print(f"{name:<15} 0x{part.address:08X}   {size_mb:6.1f} MB    {critical:<10} {part.description}")
            print("="*90)
            success = True

        elif args.command == "info":
            info = device.get_device_info()
            print(json.dumps(info, indent=2))
            success = True

        elif args.command == "batch":
            if not args.batch_file:
                parser.error("--batch-file required")
            success = BatchProcessor.execute(device, args.batch_file, args.force)

        elif args.command == "ota" and args.pac:
            # OTA flashing
            device.load_partitions()
            extracted = ArchiveExtractor.extract(args.pac, f"{args.pac}_ota")

            for part_name, img_file in extracted.items():
                if part_name in ['fdl1', 'fdl2']:
                    continue

                # Try to match partition name
                matched = False
                for p in device.partitions.keys():
                    if p in img_file.lower():
                        logger.info(f"Flashing {p}...")
                        if not device.write_partition(p, img_file, args.verify, args.force):
                            logger.error(f"Failed to flash {p}")
                            sys.exit(1)
                        matched = True
                        break

                if not matched:
                    logger.warning(f"Could not match partition for: {img_file}")

            success = True

    except KeyboardInterrupt:
        logger.warning("\n⚠ Operation cancelled by user")
        success = False
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=args.debug)
        success = False
    finally:
        device.disconnect()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
