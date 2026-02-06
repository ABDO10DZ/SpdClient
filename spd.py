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
- Fixed FDL loading silent corruption  issues
- Added --force flag for risky operations

NEW FEATURES:
- Memory-mapped file support for large ROMs
- Progress reporting with speed calculation
- Write verification option
- Critical partition protection with --force override
- Batch operations support
- Enhanced error handling and logging
- Automatic FDL extraction from PAC files
- Better CLI with --force for risky operations
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
    """SPD protocol command definitions"""
    CMD_HANDSHAKE = 0xA0
    CMD_FDL1_LOAD = 0xA1
    CMD_FDL2_LOAD = 0xA2
    CMD_READ_FLASH = 0xB0
    CMD_WRITE_FLASH = 0xB1
    CMD_ERASE_FLASH = 0xB2
    CMD_GET_INFO = 0xB3
    CMD_GET_PARTITION_INFO = 0xB4
    CMD_ACK = 0x5A
    CMD_NACK = 0xA5


class SPDTool:
    """Main SPD tool class for device communication"""
    
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.serial_conn: Optional[serial.Serial] = None
        self.fdl1_loaded = False
        self.fdl2_loaded = False
        self.chunk_size = 0x4000  # 16KB for better performance
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
            'bootloader': {'address': 0x40000, 'size': 0x80000, 'description': 'Bootloader'},
            'uboot': {'address': 0xC0000, 'size': 0x40000, 'description': 'U-Boot bootloader'},
        }

        # Critical partitions that require --force flag
        self.critical_partitions = {'bootloader', 'uboot', 'gpt', 'boot', 'recovery'}

    def connect(self) -> bool:
        """Establish serial connection with proper error handling"""
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
        
        # Verify checksum
        calc_chk = 0
        for b in resp_payload:
            calc_chk ^= b
        
        if calc_chk != resp_chk:
            logger.error(f"Checksum mismatch: expected {calc_chk:02X}, got {resp_chk:02X}")
            return b""
        
        return resp_payload

    def wait_for_ack(self, timeout: float = 5.0, retry: int = 3) -> bool:
        """FIXED: Wait for ACK with proper timeout and retry logic"""
        for attempt in range(retry):
            resp = self.send_command(SPDCommands.CMD_ACK.value, wait_response=True,
                                     response_timeout=timeout)
            if resp and len(resp) > 0:
                if resp[0] == SPDCommands.CMD_ACK.value:
                    return True
                elif resp[0] == SPDCommands.CMD_NACK.value:
                    logger.warning(f"Received NACK (attempt {attempt + 1}/{retry})")
                else:
                    logger.debug(f"Unexpected response: {resp.hex()}")
            
            if attempt < retry - 1:
                time.sleep(0.5)
        
        logger.error("Failed to receive ACK after retries")
        return False

    def handshake(self) -> bool:
        """FIXED: Perform handshake with correct protocol"""
        logger.info("Performing handshake...")
        try:
            # Send handshake command
            resp = self.send_command(SPDCommands.CMD_HANDSHAKE.value)
            
            if resp and len(resp) > 0:
                if resp[0] == SPDCommands.CMD_ACK.value:
                    logger.info("✓ Handshake successful")
                    return True
                else:
                    logger.error(f"Handshake failed: unexpected response {resp.hex()}")
            else:
                logger.error("Handshake failed: no response")
            
            return False
            
        except Exception as e:
            logger.error(f"Handshake error: {e}")
            return False

    def load_fdl1(self, fdl_path: str) -> bool:
        """Load FDL1 bootloader stage"""
        logger.info(f"Loading FDL1: {fdl_path}")
        
        if not os.path.exists(fdl_path):
            logger.error(f"FDL1 file not found: {fdl_path}")
            return False
        
        try:
            with open(fdl_path, 'rb') as f:
                fdl_data = f.read()
            
            file_size = len(fdl_data)
            logger.info(f"FDL1 size: {file_size} bytes")
            
            # Send load command with size
            cmd_data = struct.pack("<I", file_size)
            resp = self.send_command(SPDCommands.CMD_FDL1_LOAD.value, cmd_data)
            
            if not resp or resp[0] != SPDCommands.CMD_ACK.value:
                logger.error("FDL1 load command rejected")
                return False
            
            # Send FDL data in chunks with progress
            total_sent = 0
            start_time = time.time()
            
            while total_sent < file_size:
                chunk_size = min(self.chunk_size, file_size - total_sent)
                chunk = fdl_data[total_sent:total_sent + chunk_size]
                
                self.serial_conn.write(chunk)
                self.serial_conn.flush()
                
                total_sent += chunk_size
                
                # Progress reporting
                progress = (total_sent / file_size) * 100
                elapsed = time.time() - start_time
                speed = total_sent / elapsed / 1024 if elapsed > 0 else 0
                logger.info(f"Progress: {progress:.1f}% ({total_sent}/{file_size} bytes) @ {speed:.1f} KB/s")
            
            # Wait for ACK
            if not self.wait_for_ack():
                logger.error("FDL1 load verification failed")
                return False
            
            self.fdl1_loaded = True
            logger.info("✓ FDL1 loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"FDL1 load error: {e}")
            return False

    def load_fdl2(self, fdl_path: str) -> bool:
        """Load FDL2 bootloader stage"""
        logger.info(f"Loading FDL2: {fdl_path}")
        
        if not os.path.exists(fdl_path):
            logger.error(f"FDL2 file not found: {fdl_path}")
            return False
        
        try:
            with open(fdl_path, 'rb') as f:
                fdl_data = f.read()
            
            file_size = len(fdl_data)
            logger.info(f"FDL2 size: {file_size} bytes")
            
            # Send load command with size
            cmd_data = struct.pack("<I", file_size)
            resp = self.send_command(SPDCommands.CMD_FDL2_LOAD.value, cmd_data)
            
            if not resp or resp[0] != SPDCommands.CMD_ACK.value:
                logger.error("FDL2 load command rejected")
                return False
            
            # Send FDL data in chunks with progress
            total_sent = 0
            start_time = time.time()
            
            while total_sent < file_size:
                chunk_size = min(self.chunk_size, file_size - total_sent)
                chunk = fdl_data[total_sent:total_sent + chunk_size]
                
                self.serial_conn.write(chunk)
                self.serial_conn.flush()
                
                total_sent += chunk_size
                
                # Progress reporting
                progress = (total_sent / file_size) * 100
                elapsed = time.time() - start_time
                speed = total_sent / elapsed / 1024 if elapsed > 0 else 0
                logger.info(f"Progress: {progress:.1f}% ({total_sent}/{file_size} bytes) @ {speed:.1f} KB/s")
            
            # Wait for ACK
            if not self.wait_for_ack():
                logger.error("FDL2 load verification failed")
                return False
            
            self.fdl2_loaded = True
            logger.info("✓ FDL2 loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"FDL2 load error: {e}")
            return False

    def read_flash(self, address: int, length: int, output_file: str) -> bool:
        """Read data from flash memory"""
        logger.info(f"Reading flash: addr=0x{address:08X}, len=0x{length:08X} -> {output_file}")
        
        if not self.fdl2_loaded:
            logger.error("FDL2 must be loaded first")
            return False
        
        try:
            total_read = 0
            start_time = time.time()
            
            with open(output_file, 'wb') as f:
                while total_read < length:
                    chunk_size = min(self.chunk_size, length - total_read)
                    current_addr = address + total_read
                    
                    # Send read command
                    cmd_data = struct.pack("<II", current_addr, chunk_size)
                    resp = self.send_command(SPDCommands.CMD_READ_FLASH.value, cmd_data,
                                             response_timeout=10.0)
                    
                    if not resp or len(resp) < chunk_size + 1:
                        logger.error(f"Read failed at offset 0x{total_read:08X}")
                        return False
                    
                    # Extract data (skip command byte)
                    data = resp[1:chunk_size + 1]
                    f.write(data)
                    
                    total_read += len(data)
                    
                    # Progress reporting
                    progress = (total_read / length) * 100
                    elapsed = time.time() - start_time
                    speed = total_read / elapsed / 1024 if elapsed > 0 else 0
                    logger.info(f"Progress: {progress:.1f}% ({total_read}/{length} bytes) @ {speed:.1f} KB/s")
            
            logger.info(f"✓ Flash read complete: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Flash read error: {e}")
            return False

    def write_flash(self, address: int, input_file: str, verify: bool = False) -> bool:
        """FIXED: Write data to flash with proper error checking"""
        logger.info(f"Writing flash: {input_file} -> addr=0x{address:08X}")
        
        if not self.fdl2_loaded:
            logger.error("FDL2 must be loaded first")
            return False
        
        if not os.path.exists(input_file):
            logger.error(f"Input file not found: {input_file}")
            return False
        
        try:
            file_size = os.path.getsize(input_file)
            logger.info(f"File size: {file_size} bytes")
            
            total_written = 0
            start_time = time.time()
            
            # Use memory-mapped file for better performance
            with open(input_file, 'rb') as f:
                if self.use_mmap and file_size > self.chunk_size:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                        while total_written < file_size:
                            chunk_size = min(self.chunk_size, file_size - total_written)
                            current_addr = address + total_written
                            
                            chunk = mmapped[total_written:total_written + chunk_size]
                            
                            # Send write command
                            cmd_data = struct.pack("<II", current_addr, chunk_size) + chunk
                            resp = self.send_command(SPDCommands.CMD_WRITE_FLASH.value, cmd_data,
                                                     response_timeout=10.0)
                            
                            if not resp or resp[0] != SPDCommands.CMD_ACK.value:
                                logger.error(f"Write failed at offset 0x{total_written:08X}")
                                return False
                            
                            total_written += chunk_size
                            
                            # Progress reporting
                            progress = (total_written / file_size) * 100
                            elapsed = time.time() - start_time
                            speed = total_written / elapsed / 1024 if elapsed > 0 else 0
                            logger.info(f"Progress: {progress:.1f}% ({total_written}/{file_size} bytes) @ {speed:.1f} KB/s")
                else:
                    # For smaller files, read normally
                    data = f.read()
                    while total_written < file_size:
                        chunk_size = min(self.chunk_size, file_size - total_written)
                        current_addr = address + total_written
                        
                        chunk = data[total_written:total_written + chunk_size]
                        
                        # Send write command
                        cmd_data = struct.pack("<II", current_addr, chunk_size) + chunk
                        resp = self.send_command(SPDCommands.CMD_WRITE_FLASH.value, cmd_data,
                                                 response_timeout=10.0)
                        
                        if not resp or resp[0] != SPDCommands.CMD_ACK.value:
                            logger.error(f"Write failed at offset 0x{total_written:08X}")
                            return False
                        
                        total_written += chunk_size
                        
                        # Progress reporting
                        progress = (total_written / file_size) * 100
                        elapsed = time.time() - start_time
                        speed = total_written / elapsed / 1024 if elapsed > 0 else 0
                        logger.info(f"Progress: {progress:.1f}% ({total_written}/{file_size} bytes) @ {speed:.1f} KB/s")
            
            # Verify if requested
            if verify:
                logger.info("Verifying write...")
                verify_file = input_file + ".verify"
                if self.read_flash(address, file_size, verify_file):
                    with open(input_file, 'rb') as f1, open(verify_file, 'rb') as f2:
                        if f1.read() == f2.read():
                            logger.info("✓ Verification passed")
                            os.remove(verify_file)
                        else:
                            logger.error("✗ Verification failed: data mismatch")
                            return False
                else:
                    logger.error("✗ Verification read failed")
                    return False
            
            logger.info(f"✓ Flash write complete")
            return True
            
        except Exception as e:
            logger.error(f"Flash write error: {e}")
            return False

    def erase_flash(self, address: int, length: int) -> bool:
        """Erase flash memory region"""
        logger.info(f"Erasing flash: addr=0x{address:08X}, len=0x{length:08X}")
        
        if not self.fdl2_loaded:
            logger.error("FDL2 must be loaded first")
            return False
        
        try:
            # Send erase command
            cmd_data = struct.pack("<II", address, length)
            resp = self.send_command(SPDCommands.CMD_ERASE_FLASH.value, cmd_data,
                                     response_timeout=30.0)
            
            if resp and resp[0] == SPDCommands.CMD_ACK.value:
                logger.info("✓ Flash erase complete")
                return True
            else:
                logger.error("Flash erase failed")
                return False
                
        except Exception as e:
            logger.error(f"Flash erase error: {e}")
            return False

    def get_device_info(self) -> Dict:
        """Get device information"""
        logger.info("Getting device info...")
        
        try:
            resp = self.send_command(SPDCommands.CMD_GET_INFO.value)
            
            if resp and len(resp) > 0:
                # Parse device info (format may vary by device)
                info = {
                    'raw_response': resp.hex(),
                    'fdl1_loaded': self.fdl1_loaded,
                    'fdl2_loaded': self.fdl2_loaded,
                }
                return info
            else:
                logger.warning("No device info received")
                return {}
                
        except Exception as e:
            logger.error(f"Get device info error: {e}")
            return {}

    def list_partitions(self) -> Dict[str, Dict]:
        """List available partitions"""
        logger.info("Listing partitions...")
        
        # Try to get partitions from device
        try:
            resp = self.send_command(SPDCommands.CMD_GET_PARTITION_INFO.value)
            if resp and len(resp) > 1:
                # Parse partition info (implementation depends on device protocol)
                # For now, use common partitions
                self.partitions = self.common_partitions.copy()
            else:
                logger.warning("Could not get partitions from device, using common layout")
                self.partitions = self.common_partitions.copy()
        except:
            logger.warning("Using common partition layout")
            self.partitions = self.common_partitions.copy()
        
        return self.partitions

    def _check_partition_critical(self, partition_name: str, force: bool = False) -> bool:
        """Check if partition is critical and require force flag"""
        if partition_name in self.critical_partitions:
            if not force:
                logger.error(f"⚠ '{partition_name}' is a CRITICAL partition!")
                logger.error(f"⚠ Writing/erasing this partition may brick your device!")
                logger.error(f"⚠ Use --force flag to proceed at your own risk")
                return False
            else:
                logger.warning(f"⚠ FORCING operation on critical partition '{partition_name}'")
                logger.warning(f"⚠ Device may be bricked if operation fails!")
        return True

    def read_partition(self, partition_name: str, output_file: str) -> bool:
        """Read entire partition to file"""
        logger.info(f"Reading partition: {partition_name}")
        
        if partition_name not in self.partitions:
            logger.error(f"Unknown partition: {partition_name}")
            logger.info(f"Available partitions: {', '.join(self.partitions.keys())}")
            return False
        
        part_info = self.partitions[partition_name]
        return self.read_flash(part_info['address'], part_info['size'], output_file)

    def write_partition(self, partition_name: str, input_file: str,
                        verify: bool = False, force: bool = False) -> bool:
        """Write data to partition"""
        logger.info(f"Writing partition: {partition_name}")
        
        if partition_name not in self.partitions:
            logger.error(f"Unknown partition: {partition_name}")
            logger.info(f"Available partitions: {', '.join(self.partitions.keys())}")
            return False
        
        # Check if critical partition
        if not self._check_partition_critical(partition_name, force):
            return False
        
        part_info = self.partitions[partition_name]
        return self.write_flash(part_info['address'], input_file, verify)

    def erase_partition(self, partition_name: str, force: bool = False) -> bool:
        """Erase entire partition"""
        logger.info(f"Erasing partition: {partition_name}")
        
        if partition_name not in self.partitions:
            logger.error(f"Unknown partition: {partition_name}")
            logger.info(f"Available partitions: {', '.join(self.partitions.keys())}")
            return False
        
        # Check if critical partition
        if not self._check_partition_critical(partition_name, force):
            return False
        
        part_info = self.partitions[partition_name]
        return self.erase_flash(part_info['address'], part_info['size'])

    def backup_partition(self, partition_name: str, backup_dir: str = "backups") -> bool:
        """Backup partition to timestamped file"""
        logger.info(f"Backing up partition: {partition_name}")
        
        if partition_name not in self.partitions:
            logger.error(f"Unknown partition: {partition_name}")
            return False
        
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate timestamped filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(backup_dir, f"{partition_name}_{timestamp}.img")
        
        return self.read_partition(partition_name, output_file)

    def extract_pac(self, pac_file: str, output_dir: str = None) -> List[str]:
        """Extract FDL files from PAC firmware package"""
        logger.info(f"Extracting PAC file: {pac_file}")
        
        if not os.path.exists(pac_file):
            logger.error(f"PAC file not found: {pac_file}")
            return []
        
        if output_dir is None:
            output_dir = os.path.splitext(pac_file)[0] + "_extracted"
        
        os.makedirs(output_dir, exist_ok=True)
        
        extracted_files = []
        
        try:
            # PAC files are typically ZIP archives
            if zipfile.is_zipfile(pac_file):
                with zipfile.ZipFile(pac_file, 'r') as zip_ref:
                    # Look for FDL files
                    for file_info in zip_ref.filelist:
                        filename = file_info.filename.lower()
                        if 'fdl' in filename or filename.endswith('.bin'):
                            extract_path = os.path.join(output_dir, os.path.basename(file_info.filename))
                            with zip_ref.open(file_info) as source, open(extract_path, 'wb') as target:
                                target.write(source.read())
                            extracted_files.append(extract_path)
                            logger.info(f"Extracted: {extract_path}")
            else:
                logger.error("PAC file is not a valid ZIP archive")
                return []
            
            if extracted_files:
                logger.info(f"✓ Extracted {len(extracted_files)} files to {output_dir}")
            else:
                logger.warning("No FDL files found in PAC")
            
            return extracted_files
            
        except Exception as e:
            logger.error(f"PAC extraction error: {e}")
            return []

    def batch_operations(self, operations: List[Dict], force: bool = False) -> bool:
        """Execute batch operations from list"""
        logger.info(f"Executing {len(operations)} batch operations...")
        
        for i, op in enumerate(operations):
            logger.info(f"Operation {i+1}/{len(operations)}: {op.get('type', 'unknown')}")
            
            try:
                op_type = op.get('type')
                success = False
                
                if op_type == 'read':
                    success = self.read_flash(op['address'], op['length'], op['output'])
                elif op_type == 'write':
                    success = self.write_flash(op['address'], op['input'], op.get('verify', False))
                elif op_type == 'erase':
                    success = self.erase_flash(op['address'], op['length'])
                elif op_type == 'readpart':
                    success = self.read_partition(op['partition'], op['output'])
                elif op_type == 'writepart':
                    success = self.write_partition(op['partition'], op['input'],
                                                    op.get('verify', False), force)
                elif op_type == 'erasepart':
                    success = self.erase_partition(op['partition'], force)
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
    """Main entry point with improved CLI"""
    parser = argparse.ArgumentParser(
        description="SPD BootROM tool with partition support - Enhanced with --force flag",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available partitions
  python spdtool.py listparts

  # Read boot partition with FDLs
  python spdtool.py /dev/ttyUSB0 readpart boot boot_backup.bin --fdl1 fdl1.bin --fdl2 fdl2.bin

  # Write recovery partition with verification (requires --force for critical partitions)
  python spdtool.py /dev/ttyUSB0 writepart recovery recovery.img --fdl1 fdl1.bin --fdl2 fdl2.bin --verify --force

  # Backup system partition
  python spdtool.py /dev/ttyUSB0 backup system

  # Low-level flash read
  python spdtool.py /dev/ttyUSB0 read 0x100000 0x400000 boot_dump.bin --fdl2 fdl2.bin

  # Extract and auto-load FDLs from PAC firmware
  python spdtool.py extractpac firmware.pac

  # Use extracted FDLs automatically
  python spdtool.py /dev/ttyUSB0 readpart boot boot.img --pac firmware.pac
        """
    )
    
    parser.add_argument("port", nargs="?", help="Serial port (e.g. /dev/ttyUSB0, COM3)")
    parser.add_argument("command", choices=[
        "handshake", "loadfdl1", "loadfdl2", "read", "write", "erase",
        "readpart", "writepart", "erasepart", "backup", "listparts", "info", "extractpac", "batch"
    ], help="Command to execute")
    parser.add_argument("args", nargs="*", help="Command arguments")
    
    # Connection options
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Serial timeout in seconds")
    
    # FDL options
    parser.add_argument("--fdl1", help="FDL1 loader path")
    parser.add_argument("--fdl2", help="FDL2 loader path")
    parser.add_argument("--pac", help="PAC file to extract FDLs from (auto-loads FDLs)")
    
    # Operation options
    parser.add_argument("--verify", action="store_true", help="Verify write operations")
    parser.add_argument("--force", action="store_true",
                        help="Force risky operations on critical partitions (bootloader, boot, recovery, etc.)")
    
    # Performance options
    parser.add_argument("--no-mmap", action="store_true", help="Disable memory-mapped files")
    parser.add_argument("--chunk-size", type=int, default=0x4000,
                        help="Transfer chunk size in bytes (default: 16384)")
    
    # Debug options
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--batch-file", help="JSON file with batch operations")

    args = parser.parse_args()

    # Set logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle non-port commands
    if args.command == "listparts":
        tool = SPDTool("dummy")
        partitions = tool.common_partitions
        print("\n" + "="*90)
        print("Available partitions (common SPD layout)")
        print("="*90)
        print(f"{'Name':<15} {'Address':<12} {'Size':<12} {'Critical':<10} {'Description'}")
        print("-"*90)
        for name, info in sorted(partitions.items()):
            size_mb = info['size'] / (1024*1024)
            critical = "⚠ YES" if name in tool.critical_partitions else "No"
            print(f"{name:<15} 0x{info['address']:08X}   {size_mb:6.1f} MB    {critical:<10} {info['description']}")
        print("="*90)
        print("\nNote: Critical partitions require --force flag for write/erase operations")
        return

    if args.command == "extractpac":
        if len(args.args) < 1:
            parser.error("Usage: extractpac <pac_file> [output_dir]")
        pac_file = args.args[0]
        output_dir = args.args[1] if len(args.args) > 1 else None
        tool = SPDTool("dummy")
        fdl_files = tool.extract_pac(pac_file, output_dir)
        if fdl_files:
            print(f"\n✓ Extracted FDL files:")
            for f in fdl_files:
                print(f"  - {f}")
            print(f"\nYou can now use these FDLs with --fdl1 and --fdl2 options")
        sys.exit(0 if fdl_files else 1)

    if not args.port:
        parser.error("Port required for this command")

    # Create tool instance
    tool = SPDTool(args.port, args.baud, args.timeout)
    tool.chunk_size = args.chunk_size
    tool.use_mmap = not args.no_mmap

    success = False
    
    try:
        # Establish connection
        if not tool.connect():
            logger.error("Failed to connect to device")
            sys.exit(1)

        # Auto-extract and load FDLs from PAC if provided
        if args.pac:
            logger.info(f"Auto-extracting FDLs from PAC: {args.pac}")
            fdl_files = tool.extract_pac(args.pac)
            if fdl_files:
                # Try to identify FDL1 and FDL2
                for fdl_file in fdl_files:
                    filename = os.path.basename(fdl_file).lower()
                    if 'fdl1' in filename and not args.fdl1:
                        args.fdl1 = fdl_file
                        logger.info(f"Auto-detected FDL1: {fdl_file}")
                    elif 'fdl2' in filename and not args.fdl2:
                        args.fdl2 = fdl_file
                        logger.info(f"Auto-detected FDL2: {fdl_file}")

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
            addr = int(args.args[0], 16) if args.args[0].startswith('0x') else int(args.args[0])
            length = int(args.args[1], 16) if args.args[1].startswith('0x') else int(args.args[1])
            outfile = args.args[2]
            success = tool.read_flash(addr, length, outfile)

        elif args.command == "write":
            if len(args.args) < 2:
                parser.error("Usage: write <address> <input_file>")
            addr = int(args.args[0], 16) if args.args[0].startswith('0x') else int(args.args[0])
            infile = args.args[1]
            success = tool.write_flash(addr, infile, args.verify)

        elif args.command == "erase":
            if len(args.args) < 2:
                parser.error("Usage: erase <address> <length>")
            addr = int(args.args[0], 16) if args.args[0].startswith('0x') else int(args.args[0])
            length = int(args.args[1], 16) if args.args[1].startswith('0x') else int(args.args[1])
            success = tool.erase_flash(addr, length)

        elif args.command == "readpart":
            if len(args.args) < 2:
                parser.error("Usage: readpart <partition_name> <output_file>")
            part_name = args.args[0]
            outfile = args.args[1]
            # Initialize partitions first
            tool.list_partitions()
            success = tool.read_partition(part_name, outfile)

        elif args.command == "writepart":
            if len(args.args) < 2:
                parser.error("Usage: writepart <partition_name> <input_file>")
            part_name = args.args[0]
            infile = args.args[1]
            # Initialize partitions first
            tool.list_partitions()
            success = tool.write_partition(part_name, infile, args.verify, args.force)

        elif args.command == "erasepart":
            if len(args.args) < 1:
                parser.error("Usage: erasepart <partition_name>")
            part_name = args.args[0]
            # Initialize partitions first
            tool.list_partitions()
            success = tool.erase_partition(part_name, args.force)

        elif args.command == "backup":
            if len(args.args) < 1:
                parser.error("Usage: backup <partition_name> [backup_dir]")
            part_name = args.args[0]
            backup_dir = args.args[1] if len(args.args) > 1 else "backups"
            # Initialize partitions first
            tool.list_partitions()
            success = tool.backup_partition(part_name, backup_dir)

        elif args.command == "listparts":
            partitions = tool.list_partitions()
            print("\n" + "="*90)
            print("Available partitions")
            print("="*90)
            print(f"{'Name':<15} {'Address':<12} {'Size':<12} {'Critical':<10} {'Description'}")
            print("-"*90)
            for name, info in sorted(partitions.items()):
                size_mb = info['size'] / (1024*1024)
                critical = "⚠ YES" if name in tool.critical_partitions else "No"
                print(f"{name:<15} 0x{info['address']:08X}   {size_mb:6.1f} MB    {critical:<10} {info['description']}")
            print("="*90)
            success = True

        elif args.command == "info":
            info = tool.get_device_info()
            print(json.dumps(info, indent=2))
            success = True

        elif args.command == "batch":
            if not args.batch_file:
                parser.error("--batch-file required for batch command")
            with open(args.batch_file, 'r') as f:
                operations = json.load(f)
            success = tool.batch_operations(operations, args.force)

    except KeyboardInterrupt:
        logger.warning("\n⚠ Operation cancelled by user")
        success = False
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=args.debug)
        success = False
    finally:
        tool.disconnect()
    
    # Exit with proper code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
