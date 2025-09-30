#!/usr/bin/env python3
"""
spdtool.py - Enhanced SPD (Spreadtrum/Unisoc) BootROM access tool
Now with partition name support for user-friendly operations.
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
from typing import Optional, List, Dict, Tuple
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SPDTool")

class SPDCommands(Enum):
    CMD_HANDSHAKE = 0xA0
    CMD_FDL1_LOAD = 0xA1
    CMD_FDL2_LOAD = 0xA2
    CMD_READ_FLASH = 0xB0
    CMD_WRITE_FLASH = 0xB1
    CMD_ERASE_FLASH = 0xB2
    CMD_GET_INFO = 0xB3
    CMD_GET_PARTITION_INFO = 0xB4  # New command for partition info
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
        self.chunk_size = 0x1000
        self.partitions: Dict[str, Dict] = {}  # Partition name -> {address, size, type}
        
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

    def connect(self) -> bool:
        try:
            self.serial_conn = serial.Serial(
                self.port, self.baudrate, timeout=self.timeout,
                bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )
            time.sleep(0.5)
            logger.info(f"Connected to {self.port} at {self.baudrate}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False

    def disconnect(self):
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
            logger.info("Disconnected")

    def send_command(self, command: int, data: bytes = b"", wait_response: bool = True, 
                   response_timeout: float = 5.0) -> bytes:
        if not self.serial_conn:
            raise Exception("Not connected")

        length = 1 + len(data)
        header = struct.pack("<H", length)
        payload = bytes([command]) + data
        checksum = 0
        for b in payload:
            checksum ^= b
        packet = b"\x7E" + header + payload + bytes([checksum]) + b"\x7E"

        self.serial_conn.write(packet)
        self.serial_conn.flush()

        if not wait_response:
            return b""

        start_time = time.time()
        resp = b""
        while time.time() - start_time < response_timeout:
            if self.serial_conn.in_waiting:
                resp += self.serial_conn.read(self.serial_conn.in_waiting)
                if resp.endswith(b"\x7E") and resp.startswith(b"\x7E"):
                    return self._parse_response(resp)
            time.sleep(0.01)
        return b""

    def _parse_response(self, response: bytes) -> bytes:
        frame_data = response[1:-1]
        if len(frame_data) < 3:
            return b""
        resp_len = struct.unpack("<H", frame_data[0:2])[0]
        resp_payload = frame_data[2:-1]
        resp_chk = frame_data[-1]
        calc_chk = 0
        for b in resp_payload:
            calc_chk ^= b
        if resp_chk != calc_chk:
            logger.warning("Checksum mismatch")
            return b""
        return resp_payload

    def handshake(self, max_attempts: int = 10) -> bool:
        logger.info("Trying handshake...")
        for attempt in range(max_attempts):
            self.serial_conn.write(b"\x7E")
            self.serial_conn.flush()
            time.sleep(0.1)
            resp = self.serial_conn.read(64)
            if resp:
                if any(x in resp for x in [b"READY", b"SPRD", b"UNISOC", b"\x7E"]):
                    logger.info("Handshake successful")
                    return True
        logger.error("Handshake failed")
        return False

    def load_fdl(self, fdl_path: str, is_fdl2: bool = False) -> bool:
        if not os.path.exists(fdl_path):
            logger.error(f"FDL not found: {fdl_path}")
            return False
        with open(fdl_path, "rb") as f:
            data = f.read()
        cmd = SPDCommands.CMD_FDL2_LOAD.value if is_fdl2 else SPDCommands.CMD_FDL1_LOAD.value
        resp = self.send_command(cmd, struct.pack("<I", len(data)))
        if not resp:
            return False
        for off in range(0, len(data), self.chunk_size):
            chunk = data[off:off+self.chunk_size]
            header = struct.pack("<II", off, len(chunk))
            self.serial_conn.write(header + chunk)
            ack = self.serial_conn.read(1)
            if not ack or ack[0] != SPDCommands.CMD_ACK.value:
                logger.warning(f"No ACK for chunk {off}")
        if is_fdl2:
            self.fdl2_loaded = True
            # Try to read partition table after FDL2 loads
            self._try_read_partition_table()
        else:
            self.fdl1_loaded = True
        logger.info(f"Loaded {'FDL2' if is_fdl2 else 'FDL1'} successfully")
        return True

    def load_fdl1(self, fdl_path: str): return self.load_fdl(fdl_path, False)
    def load_fdl2(self, fdl_path: str): return self.load_fdl(fdl_path, True)

    def _try_read_partition_table(self):
        """Try to read partition table from device"""
        try:
            # Try to get partition info command
            resp = self.send_command(SPDCommands.CMD_GET_PARTITION_INFO.value)
            if resp and len(resp) > 8:
                # Parse partition table (simplified - actual format varies)
                # This would need to be adapted to your specific device's format
                logger.info("Found device partition table")
                # For now, we'll use common partitions as fallback
                self.partitions = self.common_partitions.copy()
            else:
                logger.info("Using common partition table as fallback")
                self.partitions = self.common_partitions.copy()
        except:
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

    def read_partition(self, partition_name: str, outfile: str) -> bool:
        """Read entire partition by name"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required")
            return False
        
        addr, size = self.get_partition_info(partition_name)
        logger.info(f"Reading partition '{partition_name}' (0x{addr:08X}, {size} bytes) to {outfile}")
        return self.read_flash(addr, size, outfile)

    def write_partition(self, partition_name: str, infile: str) -> bool:
        """Write entire partition by name"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required")
            return False
        
        addr, size = self.get_partition_info(partition_name)
        
        # Check file size
        file_size = os.path.getsize(infile)
        if file_size > size:
            logger.error(f"File size {file_size} exceeds partition size {size}")
            return False
            
        logger.info(f"Writing {infile} to partition '{partition_name}' (0x{addr:08X})")
        return self.write_flash(addr, infile)

    def erase_partition(self, partition_name: str) -> bool:
        """Erase entire partition by name"""
        if not self.fdl2_loaded:
            logger.error("FDL2 required")
            return False
        
        addr, size = self.get_partition_info(partition_name)
        logger.info(f"Erasing partition '{partition_name}' (0x{addr:08X}, {size} bytes)")
        return self.erase_flash(addr, size)

    def backup_partition(self, partition_name: str, backup_dir: str = "backups") -> bool:
        """Backup partition with automatic filename"""
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
            
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        outfile = os.path.join(backup_dir, f"{partition_name}_backup_{timestamp}.bin")
        return self.read_partition(partition_name, outfile)

    # Original low-level methods (now used internally)
    def read_flash(self, addr: int, length: int, outfile: str) -> bool:
        if not self.fdl2_loaded:
            logger.error("FDL2 required")
            return False
        resp = self.send_command(SPDCommands.CMD_READ_FLASH.value, struct.pack("<II", addr, length))
        if not resp: 
            return False
        data = b""
        while len(data) < length:
            chunk = self.serial_conn.read(min(4096, length - len(data)))
            if not chunk: 
                break
            data += chunk
            if len(data) % (1024*1024) == 0:
                logger.info(f"Read {len(data)}/{length} bytes")
        if len(data) == length:
            with open(outfile, "wb") as f: 
                f.write(data)
            logger.info(f"Dump saved: {outfile}")
            return True
        return False

    def write_flash(self, addr: int, infile: str) -> bool:
        if not self.fdl2_loaded: 
            return False
        with open(infile, "rb") as f: 
            data = f.read()
        resp = self.send_command(SPDCommands.CMD_WRITE_FLASH.value, struct.pack("<II", addr, len(data)))
        if not resp: 
            return False
        for off in range(0, len(data), self.chunk_size):
            chunk = data[off:off+self.chunk_size]
            self.serial_conn.write(chunk)
            ack = self.serial_conn.read(1)
            if not ack or ack[0] != SPDCommands.CMD_ACK.value:
                logger.warning(f"No ACK for chunk {off}")
        logger.info("Write done")
        return True

    def erase_flash(self, addr: int, length: int) -> bool:
        resp = self.send_command(SPDCommands.CMD_ERASE_FLASH.value, struct.pack("<II", addr, length))
        return bool(resp)

    def get_device_info(self) -> dict:
        resp = self.send_command(SPDCommands.CMD_GET_INFO.value)
        return {"raw": resp.hex()} if resp else {}

    def extract_pac(self, pac_path: str, outdir: str = "pac_extracted") -> List[str]:
        if not os.path.exists(pac_path): 
            return []
        os.makedirs(outdir, exist_ok=True)
        candidates = []
        try:
            with zipfile.ZipFile(pac_path, "r") as z:
                z.extractall(outdir)
                for root, _, files in os.walk(outdir):
                    for fn in files:
                        if "fdl" in fn.lower():
                            candidates.append(os.path.join(root, fn))
        except zipfile.BadZipFile:
            logger.warning("PAC not zip, skipping")
        return candidates

def main():
    parser = argparse.ArgumentParser(description="SPD BootROM tool with partition support")
    parser.add_argument("port", nargs="?", help="Serial port (e.g. /dev/ttyUSB0, COM3)")
    parser.add_argument("command", choices=[
        "handshake", "loadfdl1", "loadfdl2", "read", "write", "erase", 
        "readpart", "writepart", "erasepart", "backup", "listparts", "info", "extractpac"
    ])
    parser.add_argument("args", nargs="*")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--fdl1", help="FDL1 loader path (for partition operations)")
    parser.add_argument("--fdl2", help="FDL2 loader path (for partition operations)")
    
    args = parser.parse_args()

    # Handle non-port commands
    if args.command == "listparts" and not args.port:
        tool = SPDTool("dummy")
        partitions = tool.common_partitions
        print("\nAvailable partitions (common SPD layout):")
        print("-" * 80)
        for name, info in sorted(partitions.items()):
            print(f"{name:15} 0x{info['address']:08X} {info['size']:8} bytes  {info['description']}")
        return

    if not args.port:
        parser.error("Port required for this command")

    tool = SPDTool(args.port, args.baud)
    if not tool.connect(): 
        sys.exit(1)

    try:
        # Load FDLs if provided for partition operations
        if args.command in ["readpart", "writepart", "erasepart", "backup"]:
            if args.fdl1:
                if not tool.load_fdl1(args.fdl1):
                    logger.error("FDL1 load failed")
                    return
            if args.fdl2:
                if not tool.load_fdl2(args.fdl2):
                    logger.error("FDL2 load failed")
                    return

        if args.command == "handshake":
            tool.handshake()
            
        elif args.command == "loadfdl1":
            tool.load_fdl1(args.args[0])
            
        elif args.command == "loadfdl2":
            tool.load_fdl2(args.args[0])
            
        elif args.command == "read":
            addr, length, outfile = int(args.args[0],16), int(args.args[1],16), args.args[2]
            tool.read_flash(addr, length, outfile)
            
        elif args.command == "write":
            addr, infile = int(args.args[0],16), args.args[1]
            tool.write_flash(addr, infile)
            
        elif args.command == "erase":
            addr, length = int(args.args[0],16), int(args.args[1],16)
            tool.erase_flash(addr, length)
            
        elif args.command == "readpart":
            part_name, outfile = args.args[0], args.args[1]
            tool.read_partition(part_name, outfile)
            
        elif args.command == "writepart":
            part_name, infile = args.args[0], args.args[1]
            tool.write_partition(part_name, infile)
            
        elif args.command == "erasepart":
            part_name = args.args[0]
            tool.erase_partition(part_name)
            
        elif args.command == "backup":
            part_name = args.args[0]
            backup_dir = args.args[1] if len(args.args) > 1 else "backups"
            tool.backup_partition(part_name, backup_dir)
            
        elif args.command == "listparts":
            partitions = tool.list_partitions()
            print("\nAvailable partitions:")
            print("-" * 80)
            for name, info in sorted(partitions.items()):
                print(f"{name:15} 0x{info['address']:08X} {info['size']:8} bytes  {info['description']}")
                
        elif args.command == "info":
            print(tool.get_device_info())
            
        elif args.command == "extractpac":
            tool.extract_pac(args.args[0])
            
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        tool.disconnect()

if __name__ == "__main__":
    main()