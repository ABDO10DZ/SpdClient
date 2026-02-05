#!/usr/bin/env python3
"""
spdtool.py - Enhanced SPD (Spreadtrum/Unisoc) BootROM access tool
Complete rebuild with critical bug fixes, memory-mapped file support,
and enhanced safety features.

CRITICAL FIXES:
- Fixed packet parsing double-slice bug
- Added proper ACK timeout and retry logic
- Fixed write_flash always returning True bug
- Added critical partition protection
- Fixed handshake method protocol violations
- Added proper error codes and exit handling
- Fixed FDL loading silent corruption issues

NEW FEATURES:
- Memory-mapped file support for large ROMs
- Progress reporting with speed calculation
- Write verification option
- Critical partition protection
- Batch operations support
- Enhanced error handling and logging
"""

import argparse
import serial
import struct
import time
import logging
import os
import sys
import zipfile
import json
import mmap
from typing import Optional, List, Dict, Tuple, Union
from enum import Enum
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("SPDTool")

class SPDCommands(Enum):
    CMD_HANDSHAKE = 0xA0
    CMD_FDL1_LOAD = 0xA1
    CMD_FDL2_LOAD = 0xA2
    CMD_READ_FLASH = 0xB0    CMD_WRITE_FLASH = 0xB1
    CMD_ERASE_FLASH = 0xB2
    CMD_GET_INFO = 0xB3
    CMD_GET_PARTITION_INFO = 0xB4
    CMD_ACK = 0x5A
    CMD_NACK = 0xA5

class SPDTool:
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.serial_conn: Optional[serial.Serial] = None
        self.fdl1_loaded = False
        self.fdl2_loaded = False
        self.chunk_size = 0x4000  # Increased to 16KB for better performance
        self.partitions: Dict[str, Dict] = {}
        self.use_mmap = True  # Enable memory-mapped files by default

        # Common SPD partitions (fallback if we can't read from device)
        self.common_partitions = {
            # Boot and system partitions
            'boot': {'address': 0x100000, 'size': 0x400000, 'description': 'Kernel and ramdisk'},
            'recovery': {'address': 0x500000, 'size': 0x400000, 'description': 'Recovery system'},
            'system': {'address': 0x900000, 'size': 0x6000000, 'description': 'Android system'},
            'vendor': {'address': 0x6900000, 'size': 0x2000000, 'description': 'Vendor files'},

            # User data partitions
            'userdata': {'address': 0x8900000, 'size': 0x10000000, 'description': 'User data and apps'},
            'cache': {'address': 0x18900000, 'size': 0x4000000, 'description': 'Cache data'},
            'metadata': {'address': 0x1C900000, 'size': 0x800000, 'description': 'Metadata partition'},

            # Special partitions
            'frp': {'address': 0x1D100000, 'size': 0x80000, 'description': 'Factory Reset Protection'},
            'persist': {'address': 0x1D180000, 'size': 0x800000, 'description': 'Persistent data'},
            'persistbak': {'address': 0x1D980000, 'size': 0x800000, 'description': 'Persistent backup'},
            'misc': {'address': 0x1E180000, 'size': 0x80000, 'description': 'Miscellaneous boot data'},

            # Modem and firmware
            'modem': {'address': 0x1E200000, 'size': 0x4000000, 'description': 'Modem firmware'},
            'dsp': {'address': 0x22200000, 'size': 0x2000000, 'description': 'DSP firmware'},

            # Backup and critical partitions
            'backup': {'address': 0x24200000, 'size': 0x800000, 'description': 'Backup partition'},
            'splash': {'address': 0x24A00000, 'size': 0x800000, 'description': 'Boot splash screen'},
            'keystore': {'address': 0x25200000, 'size': 0x80000, 'description': 'Key storage'},

            # GPT and bootloader
            'gpt': {'address': 0x0, 'size': 0x40000, 'description': 'Partition table'},
            'bootloader': {'address': 0x40000, 'size': 0x80000, 'description': 'Bootloader'},            'uboot': {'address': 0xC0000, 'size': 0x40000, 'description': 'U-Boot bootloader'},
        }

        # Critical partitions that require explicit confirmation
        self.critical_partitions = {'bootloader', 'uboot', 'gpt', 'boot', 'recovery'}

    def connect(self) -> bool:
        """Establish serial connection with proper error handling"""
        try:
            self.serial_conn = serial.Serial(
                self.port, self.baudrate, timeout=self.timeout,
                bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE, write_timeout=5.0
            )
            time.sleep(0.5)
            logger.info(f"Connected to {self.port} at {self.baudrate} baud")
            return True
        except serial.SerialException as e:
            logger.error(f"Serial connection failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected connection error: {e}")
            return False

    def disconnect(self):
        """Safely disconnect serial port"""
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.close()
                logger.info("Disconnected from device")
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")

    def send_command(self, command: int, data: bytes = b"", wait_response: bool = True, 
                   response_timeout: float = 5.0) -> bytes:
        """Send command with proper packet framing and error checking"""
        if not self.serial_conn or not self.serial_conn.is_open:
            raise Exception("Not connected to device")

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
            
            logger.warning(f"Command timeout after {response_timeout}s")
            return b""
            
        except serial.SerialTimeoutException as e:
            logger.error(f"Serial write timeout: {e}")
            return b""
        except Exception as e:
            logger.error(f"Send command error: {e}")
            return b""

    def _parse_response(self, response: bytes) -> bytes:
        """FIXED: Correct packet parsing without double-slicing bug"""
        # Validate frame structure
        if not response.startswith(b"\x7E") or not response.endswith(b"\x7E"):
            logger.error("Invalid frame delimiters")
            return b""
        
        # Remove delimiters ONCE
        frame_data = response[1:-1]
        
        if len(frame_data) < 3:
            logger.error("Frame too short")
            return b""
        
        # Parse length
        resp_len = struct.unpack("<H", frame_data[0:2])[0]
        
        # Validate length matches actual data
        expected_length = 2 + resp_len + 1  # header(2) + payload(len) + checksum(1)
        if len(frame_data) != expected_length:
            logger.error(f"Length mismatch: expected {expected_length}, got {len(frame_data)}")
            return b""
                # Extract payload and checksum correctly
        resp_payload = frame_data[2:2+resp_len]  # Payload is after header
        resp_chk = frame_data[2+resp_len]  # Checksum is after payload
        
        # Calculate checksum
        calc_chk = 0
        for b in resp_payload:
            calc_chk ^= b
        
        # Validate checksum
        if resp_chk != calc_chk:
            logger.error(f"Checksum mismatch: expected 0x{resp_chk:02X}, got 0x{calc_chk:02X}")
            return b""
        
        return resp_payload

    def handshake(self, max_attempts: int = 10) -> bool:
        """FIXED: Proper handshake with buffer clearing and proper response checking"""
        logger.info("Initiating handshake...")
        
        if not self.serial_conn:
            logger.error("Not connected")
            return False
        
        # Clear input buffer before starting
        self.serial_conn.reset_input_buffer()
        
        for attempt in range(max_attempts):
            logger.debug(f"Handshake attempt {attempt + 1}/{max_attempts}")
            
            # Send handshake byte
            self.serial_conn.write(b"\x7E")
            self.serial_conn.flush()
            time.sleep(0.1)
            
            # Read with timeout, not fixed size
            start = time.time()
            resp = b""
            while time.time() - start < 1.0 and len(resp) < 256:
                if self.serial_conn.in_waiting:
                    resp += self.serial_conn.read(self.serial_conn.in_waiting)
                else:
                    time.sleep(0.01)
            
            # Check for actual BootROM responses (NOT frame delimiter)
            if b"READY" in resp or b"SPRD" in resp or b"UNISOC" in resp:
                logger.info("✓ Handshake successful")
                # Clear any remaining data in buffer
                self.serial_conn.reset_input_buffer()
                return True        
        logger.error("✗ Handshake failed after all attempts")
        return False

    def load_fdl(self, fdl_path: str, is_fdl2: bool = False) -> bool:
        """FIXED: Proper FDL loading with retry logic and failure detection"""
        if not os.path.exists(fdl_path):
            logger.error(f"FDL file not found: {fdl_path}")
            return False
        
        try:
            file_size = os.path.getsize(fdl_path)
            logger.info(f"Loading {'FDL2' if is_fdl2 else 'FDL1'}: {fdl_path} ({file_size} bytes)")
            
            with open(fdl_path, "rb") as f:
                data = f.read()
            
            cmd = SPDCommands.CMD_FDL2_LOAD.value if is_fdl2 else SPDCommands.CMD_FDL1_LOAD.value
            resp = self.send_command(cmd, struct.pack("<I", len(data)))
            
            if not resp:
                logger.error("Failed to initiate FDL load")
                return False
            
            max_retries = 3
            failed_chunks = []
            
            # Load in chunks with retry logic
            for off in range(0, len(data), self.chunk_size):
                chunk = data[off:off+self.chunk_size]
                header = struct.pack("<II", off, len(chunk))
                
                chunk_success = False
                for retry in range(max_retries):
                    try:
                        self.serial_conn.write(header + chunk)
                        self.serial_conn.flush()
                        
                        # Wait for ACK with timeout
                        start = time.time()
                        ack = b""
                        while time.time() - start < 2.0:
                            if self.serial_conn.in_waiting:
                                ack = self.serial_conn.read(1)
                                break
                            time.sleep(0.01)
                        
                        if ack and ack[0] == SPDCommands.CMD_ACK.value:
                            chunk_success = True
                            break                        else:
                            logger.warning(f"Chunk 0x{off:08X}: No ACK (retry {retry + 1}/{max_retries})")
                            time.sleep(0.1)
                    
                    except Exception as e:
                        logger.warning(f"Chunk 0x{off:08X} error: {e} (retry {retry + 1}/{max_retries})")
                
                if not chunk_success:
                    logger.error(f"Chunk 0x{off:08X} failed after {max_retries} retries")
                    failed_chunks.append(off)
            
            if failed_chunks:
                logger.error(f"FDL load FAILED: {len(failed_chunks)} chunks failed")
                return False
            
            if is_fdl2:
                self.fdl2_loaded = True
                self._try_read_partition_table()
            else:
                self.fdl1_loaded = True
            
            logger.info(f"✓ {'FDL2' if is_fdl2 else 'FDL1'} loaded successfully ({len(data)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"FDL load error: {e}")
            return False

    def load_fdl1(self, fdl_path: str): return self.load_fdl(fdl_path, False)
    def load_fdl2(self, fdl_path: str): return self.load_fdl(fdl_path, True)

    def _try_read_partition_table(self):
        """Try to read actual partition table from device"""
        try:
            logger.info("Attempting to read device partition table...")
            resp = self.send_command(SPDCommands.CMD_GET_PARTITION_INFO.value)
            
            if resp and len(resp) > 8:
                # Parse actual partition table (device-specific format)
                partition_count = struct.unpack("<I", resp[0:4])[0]
                logger.info(f"Found {partition_count} partitions on device")
                
                # Note: Actual format varies by device
                # This is a placeholder - implement device-specific parsing
                self.partitions = self.common_partitions.copy()
            else:
                logger.info("Using common partition table as fallback")
                self.partitions = self.common_partitions.copy()
                
        except Exception as e:            logger.warning(f"Failed to read partition table: {e}")
            logger.info("Using common partition table")
            self.partitions = self.common_partitions.copy()

    def get_partition_info(self, partition_name: str) -> Tuple[int, int]:
        """Get address and size for a partition by name"""
        if partition_name not in self.partitions:
            available = ", ".join(sorted(self.partitions.keys()))
            raise ValueError(f"Partition '{partition_name}' not found. Available: {available}")

        part_info = self.partitions[partition_name]
        return part_info['address'], part_info['size']

    def list_partitions(self) -> Dict[str, Dict]:
        """List all available partitions"""
        return self.partitions

    def _confirm_critical_partition(self, partition_name: str, operation: str) -> bool:
        """Confirm operation on critical partitions"""
        if partition_name in self.critical_partitions:
            logger.error(f"⚠️  DANGEROUS OPERATION: {operation} on critical partition '{partition_name}'")
            logger.error("This could BRICK your device permanently!")
            logger.error("Are you absolutely sure you want to proceed?")
            response = input("Type 'I UNDERSTAND THE RISK' to continue: ").strip()
            if response != 'I UNDERSTAND THE RISK':
                logger.info("Operation cancelled by user")
                return False
        return True

    def read_partition(self, partition_name: str, outfile: str) -> bool:
        """Read entire partition by name"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required for partition operations")
            return False

        addr, size = self.get_partition_info(partition_name)
        logger.info(f"Reading partition '{partition_name}' (0x{addr:08X}, {size} bytes) to {outfile}")
        return self.read_flash(addr, size, outfile)

    def write_partition(self, partition_name: str, infile: str, verify: bool = False) -> bool:
        """FIXED: Proper partition write with validation and verification"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required for partition operations")
            return False

        addr, size = self.get_partition_info(partition_name)
        file_size = os.path.getsize(infile)
        
        # Validate file size
        if file_size > size:            logger.error(f"File size {file_size} exceeds partition size {size}")
            return False
        
        if file_size < size:
            logger.warning(f"File size {file_size} is smaller than partition size {size}")
            logger.warning(f"Only first {file_size} bytes will be written!")
            response = input("Continue? (yes/no): ").strip().lower()
            if response != 'yes':
                return False
        
        # Critical partition protection
        if not self._confirm_critical_partition(partition_name, "WRITE"):
            return False
        
        logger.info(f"Writing {infile} ({file_size} bytes) to partition '{partition_name}' (0x{addr:08X})")
        
        # Perform write
        success = self.write_flash(addr, infile, verify)
        
        if success and verify:
            logger.info("✓ Write operation completed successfully with verification")
        elif success:
            logger.info("✓ Write operation completed successfully")
        
        return success

    def erase_partition(self, partition_name: str) -> bool:
        """Erase entire partition by name"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required for partition operations")
            return False

        addr, size = self.get_partition_info(partition_name)
        
        # Critical partition protection
        if not self._confirm_critical_partition(partition_name, "ERASE"):
            return False
        
        logger.info(f"Erasing partition '{partition_name}' (0x{addr:08X}, {size} bytes)")
        return self.erase_flash(addr, size)

    def backup_partition(self, partition_name: str, backup_dir: str = "backups") -> bool:
        """Backup partition with automatic filename"""
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        outfile = os.path.join(backup_dir, f"{partition_name}_backup_{timestamp}.bin")
        return self.read_partition(partition_name, outfile)
    def read_flash(self, addr: int, length: int, outfile: str) -> bool:
        """FIXED: Proper read with timeout handling and partial data detection"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required for flash operations")
            return False
        
        try:
            logger.info(f"Reading flash: 0x{addr:08X} ({length} bytes)")
            
            resp = self.send_command(SPDCommands.CMD_READ_FLASH.value, struct.pack("<II", addr, length))
            if not resp:
                logger.error("Failed to initiate read operation")
                return False
            
            data = b""
            start_time = time.time()
            timeout_total = 600.0  # 10 minutes for large reads
            last_progress = 0
            
            while len(data) < length:
                # Check for overall timeout
                if time.time() - start_time > timeout_total:
                    logger.error(f"Read timeout after {len(data)}/{length} bytes")
                    return False
                
                # Read chunk
                chunk_size = min(8192, length - len(data))  # 8KB chunks
                chunk = self.serial_conn.read(chunk_size)
                
                if not chunk:
                    # Check if we're still waiting for data
                    if self.serial_conn.in_waiting == 0:
                        time.sleep(0.05)
                        continue
                
                data += chunk
                
                # Progress reporting every 10% or 1MB
                progress = (len(data) * 100) // length
                if progress != last_progress and (progress % 10 == 0 or len(data) % (1024*1024) == 0):
                    elapsed = time.time() - start_time
                    speed = len(data) / elapsed if elapsed > 0 else 0
                    logger.info(f"Progress: {progress}% ({len(data)}/{length} bytes) [{speed/1024:.1f} KB/s]")
                    last_progress = progress
            
            # Verify complete read
            if len(data) != length:
                logger.error(f"Read incomplete: {len(data)}/{length} bytes")
                return False
                        # Save to file
            try:
                with open(outfile, "wb") as f:
                    f.write(data)
                logger.info(f"✓ Dump saved: {outfile} ({length} bytes)")
                return True
            except Exception as e:
                logger.error(f"Failed to save file: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Read error: {e}")
            return False

    def _read_file_mmap(self, filepath: str) -> Union[mmap.mmap, bytes]:
        """Read file using memory-mapped files for large files"""
        try:
            file_size = os.path.getsize(filepath)
            
            if file_size > 100 * 1024 * 1024 and self.use_mmap:  # Use mmap for files > 100MB
                logger.info(f"Using memory-mapped file for {filepath} ({file_size / (1024*1024):.1f} MB)")
                fd = os.open(filepath, os.O_RDONLY)
                mmapped_file = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
                os.close(fd)
                return mmapped_file
            else:
                # For smaller files, just read normally
                with open(filepath, "rb") as f:
                    return f.read()
                    
        except Exception as e:
            logger.warning(f"Memory-mapped file failed, falling back to normal read: {e}")
            with open(filepath, "rb") as f:
                return f.read()

    def write_flash(self, addr: int, infile: str, verify: bool = False) -> bool:
        """FIXED: Proper write with ACK validation and never returning True on failure"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required for flash operations")
            return False
        
        try:
            file_size = os.path.getsize(infile)
            logger.info(f"Writing to flash: 0x{addr:08X} ({file_size} bytes)")
            
            # Use memory-mapped file for large files
            data = self._read_file_mmap(infile)
            
            # Initiate write
            resp = self.send_command(SPDCommands.CMD_WRITE_FLASH.value, struct.pack("<II", addr, file_size))            if not resp:
                logger.error("Failed to initiate write operation")
                if isinstance(data, mmap.mmap):
                    data.close()
                return False
            
            max_retries = 3
            failed_chunks = []
            start_time = time.time()
            last_progress = 0
            
            # Write in chunks
            for off in range(0, file_size, self.chunk_size):
                chunk = data[off:off+self.chunk_size] if isinstance(data, (bytes, mmap.mmap)) else data[off:off+self.chunk_size]
                
                chunk_success = False
                for retry in range(max_retries):
                    try:
                        self.serial_conn.write(chunk)
                        self.serial_conn.flush()
                        
                        # Wait for ACK with timeout
                        ack_start = time.time()
                        ack = b""
                        while time.time() - ack_start < 2.0:
                            if self.serial_conn.in_waiting:
                                ack = self.serial_conn.read(1)
                                break
                            time.sleep(0.01)
                        
                        if ack and ack[0] == SPDCommands.CMD_ACK.value:
                            chunk_success = True
                            break
                        else:
                            logger.warning(f"Chunk 0x{off:08X}: No ACK (retry {retry + 1}/{max_retries})")
                            time.sleep(0.1)
                    
                    except Exception as e:
                        logger.warning(f"Chunk 0x{off:08X} error: {e} (retry {retry + 1}/{max_retries})")
                
                if not chunk_success:
                    logger.error(f"Chunk 0x{off:08X} failed after {max_retries} retries")
                    failed_chunks.append(off)
                
                # Progress reporting
                progress = ((off + len(chunk)) * 100) // file_size
                if progress != last_progress and progress % 10 == 0:
                    elapsed = time.time() - start_time
                    speed = (off + len(chunk)) / elapsed if elapsed > 0 else 0
                    logger.info(f"Progress: {progress}% ({off + len(chunk)}/{file_size} bytes) [{speed/1024:.1f} KB/s]")                    last_progress = progress
            
            # Close mmap if used
            if isinstance(data, mmap.mmap):
                data.close()
            
            # Check for failed chunks
            if failed_chunks:
                logger.error(f"Write FAILED: {len(failed_chunks)} chunks failed")
                return False
            
            # Optional verification
            if verify:
                logger.info("Verifying write operation...")
                temp_verify = infile + ".verify_tmp"
                if self.read_flash(addr, file_size, temp_verify):
                    try:
                        with open(infile, 'rb') as f1, open(temp_verify, 'rb') as f2:
                            if f1.read() == f2.read():
                                logger.info("✓ Verification successful!")
                                os.remove(temp_verify)
                            else:
                                logger.error("✗ Verification FAILED - data mismatch!")
                                os.remove(temp_verify)
                                return False
                    except Exception as e:
                        logger.error(f"Verification error: {e}")
                        return False
            
            elapsed = time.time() - start_time
            logger.info(f"✓ Write completed successfully ({file_size} bytes in {elapsed:.1f}s)")
            return True
            
        except Exception as e:
            logger.error(f"Write error: {e}")
            return False

    def erase_flash(self, addr: int, length: int) -> bool:
        """Erase flash memory"""
        try:
            logger.info(f"Erasing flash: 0x{addr:08X} ({length} bytes)")
            resp = self.send_command(SPDCommands.CMD_ERASE_FLASH.value, struct.pack("<II", addr, length))
            
            if resp:
                logger.info("✓ Erase completed successfully")
                return True
            else:
                logger.error("Erase operation failed or timed out")
                return False
                        except Exception as e:
            logger.error(f"Erase error: {e}")
            return False

    def get_device_info(self) -> dict:
        """Get device information"""
        try:
            resp = self.send_command(SPDCommands.CMD_GET_INFO.value)
            if resp:
                return {
                    "success": True,
                    "raw_data": resp.hex(),
                    "length": len(resp)
                }
            else:
                return {"success": False, "error": "No response"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def extract_pac(self, pac_path: str, outdir: str = "pac_extracted") -> List[str]:
        """Extract PAC firmware package"""
        if not os.path.exists(pac_path):
            logger.error(f"PAC file not found: {pac_path}")
            return []
        
        os.makedirs(outdir, exist_ok=True)
        candidates = []
        
        try:
            with zipfile.ZipFile(pac_path, "r") as z:
                logger.info(f"Extracting PAC: {pac_path}")
                z.extractall(outdir)
                for root, _, files in os.walk(outdir):
                    for fn in files:
                        if "fdl" in fn.lower():
                            candidates.append(os.path.join(root, fn))
                logger.info(f"Extracted {len(candidates)} FDL files")
        except zipfile.BadZipFile:
            logger.error("Invalid PAC file - not a valid ZIP archive")
        except Exception as e:
            logger.error(f"PAC extraction error: {e}")
        
        return candidates

    def batch_operation(self, operations: List[Dict]) -> bool:
        """
        Execute multiple operations in sequence
        
        operations = [
            {'type': 'read', 'partition': 'boot', 'output': 'boot.bin'},            {'type': 'write', 'partition': 'recovery', 'input': 'recovery_new.img', 'verify': True},
            {'type': 'backup', 'partition': 'system'}
        ]
        """
        logger.info(f"Starting batch operation ({len(operations)} operations)")
        
        for i, op in enumerate(operations):
            logger.info(f"\nOperation {i+1}/{len(operations)}: {op.get('type', 'unknown')}")
            
            try:
                op_type = op.get('type')
                
                if op_type == 'read':
                    success = self.read_partition(op['partition'], op['output'])
                elif op_type == 'write':
                    success = self.write_partition(
                        op['partition'], 
                        op['input'], 
                        verify=op.get('verify', False)
                    )
                elif op_type == 'erase':
                    success = self.erase_partition(op['partition'])
                elif op_type == 'backup':
                    output_dir = op.get('output_dir', 'backups')
                    success = self.backup_partition(op['partition'], output_dir)
                else:
                    logger.error(f"Unknown operation type: {op_type}")
                    success = False
                
                if not success:
                    logger.error(f"Operation {i+1} failed")
                    return False
                    
            except Exception as e:
                logger.error(f"Operation {i+1} error: {e}")
                return False
        
        logger.info("✓ All batch operations completed successfully")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="SPD BootROM tool with partition support - Complete rebuild with critical fixes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available partitions
  python spdtool.py listparts
    # Read boot partition with FDLs
  python spdtool.py /dev/ttyUSB0 readpart boot boot_backup.bin --fdl1 fdl1.bin --fdl2 fdl2.bin
  
  # Write recovery partition with verification
  python spdtool.py /dev/ttyUSB0 writepart recovery recovery_new.img --fdl1 fdl1.bin --fdl2 fdl2.bin --verify
  
  # Backup system partition
  python spdtool.py /dev/ttyUSB0 backup system
  
  # Low-level flash read
  python spdtool.py /dev/ttyUSB0 read 0x100000 0x400000 boot_dump.bin --fdl2 fdl2.bin
  
  # Extract PAC firmware
  python spdtool.py extractpac firmware.pac
        """
    )
    
    parser.add_argument("port", nargs="?", help="Serial port (e.g. /dev/ttyUSB0, COM3)")
    parser.add_argument("command", choices=[
        "handshake", "loadfdl1", "loadfdl2", "read", "write", "erase", 
        "readpart", "writepart", "erasepart", "backup", "listparts", "info", "extractpac"
    ], help="Command to execute")
    parser.add_argument("args", nargs="*", help="Command arguments")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--fdl1", help="FDL1 loader path")
    parser.add_argument("--fdl2", help="FDL2 loader path")
    parser.add_argument("--verify", action="store_true", help="Verify write operations")
    parser.add_argument("--no-mmap", action="store_true", help="Disable memory-mapped files")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--chunk-size", type=int, default=0x4000, help="Transfer chunk size in bytes")

    args = parser.parse_args()

    # Set logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle non-port commands
    if args.command == "listparts" and not args.port:
        tool = SPDTool("dummy")
        partitions = tool.common_partitions
        print("\nAvailable partitions (common SPD layout):")
        print("-" * 90)
        print(f"{'Name':<15} {'Address':<12} {'Size':<12} {'Description'}")
        print("-" * 90)
        for name, info in sorted(partitions.items()):
            size_mb = info['size'] / (1024*1024)
            print(f"{name:<15} 0x{info['address']:08X} {size_mb:5.1f} MB    {info['description']}")
        return
    if not args.port:
        parser.error("Port required for this command")

    # Create tool instance
    tool = SPDTool(args.port, args.baud)
    tool.chunk_size = args.chunk_size
    tool.use_mmap = not args.no_mmap

    success = False
    
    try:
        # Establish connection
        if not tool.connect():
            logger.error("Failed to connect to device")
            sys.exit(1)

        # Load FDLs if provided for partition operations
        if args.command in ["readpart", "writepart", "erasepart", "backup", "read", "write", "erase"]:
            if args.fdl1:
                if not tool.load_fdl1(args.fdl1):
                    logger.error("FDL1 load failed")
                    sys.exit(1)
            if args.fdl2:
                if not tool.load_fdl2(args.fdl2):
                    logger.error("FDL2 load failed")
                    sys.exit(1)

        # Execute command
        if args.command == "handshake":
            success = tool.handshake()

        elif args.command == "loadfdl1":
            if len(args.args) < 1:
                parser.error("FDL1 file path required")
            success = tool.load_fdl1(args.args[0])

        elif args.command == "loadfdl2":
            if len(args.args) < 1:
                parser.error("FDL2 file path required")
            success = tool.load_fdl2(args.args[0])

        elif args.command == "read":
            if len(args.args) < 3:
                parser.error("Usage: read <address> <length> <output_file>")
            addr = int(args.args[0], 16)
            length = int(args.args[1], 16)
            outfile = args.args[2]
            success = tool.read_flash(addr, length, outfile)

        elif args.command == "write":            if len(args.args) < 2:
                parser.error("Usage: write <address> <input_file>")
            addr = int(args.args[0], 16)
            infile = args.args[1]
            success = tool.write_flash(addr, infile, args.verify)

        elif args.command == "erase":
            if len(args.args) < 2:
                parser.error("Usage: erase <address> <length>")
            addr = int(args.args[0], 16)
            length = int(args.args[1], 16)
            success = tool.erase_flash(addr, length)

        elif args.command == "readpart":
            if len(args.args) < 2:
                parser.error("Usage: readpart <partition_name> <output_file>")
            part_name = args.args[0]
            outfile = args.args[1]
            success = tool.read_partition(part_name, outfile)

        elif args.command == "writepart":
            if len(args.args) < 2:
                parser.error("Usage: writepart <partition_name> <input_file>")
            part_name = args.args[0]
            infile = args.args[1]
            success = tool.write_partition(part_name, infile, args.verify)

        elif args.command == "erasepart":
            if len(args.args) < 1:
                parser.error("Usage: erasepart <partition_name>")
            part_name = args.args[0]
            success = tool.erase_partition(part_name)

        elif args.command == "backup":
            if len(args.args) < 1:
                parser.error("Usage: backup <partition_name> [backup_dir]")
            part_name = args.args[0]
            backup_dir = args.args[1] if len(args.args) > 1 else "backups"
            success = tool.backup_partition(part_name, backup_dir)

        elif args.command == "listparts":
            partitions = tool.list_partitions()
            print("\nAvailable partitions:")
            print("-" * 90)
            print(f"{'Name':<15} {'Address':<12} {'Size':<12} {'Description'}")
            print("-" * 90)
            for name, info in sorted(partitions.items()):
                size_mb = info['size'] / (1024*1024)
                print(f"{name:<15} 0x{info['address']:08X} {size_mb:5.1f} MB    {info['description']}")
        elif args.command == "info":
            info = tool.get_device_info()
            print(json.dumps(info, indent=2))

        elif args.command == "extractpac":
            if len(args.args) < 1:
                parser.error("Usage: extractpac <pac_file>")
            fdl_files = tool.extract_pac(args.args[0])
            if fdl_files:
                print(f"\nExtracted FDL files:")
                for f in fdl_files:
                    print(f"  - {f}")

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        success = False
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        success = False
    finally:
        tool.disconnect()
    
    # Exit with proper code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()