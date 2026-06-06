#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

# Auto-reexecute using virtualenv if available locally
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
VENV_PYTHON = os.path.join(PROJECT_DIR, "venv", "bin", "python3")
if os.path.exists(VENV_PYTHON) and os.path.realpath(sys.executable) != os.path.realpath(VENV_PYTHON):
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

# Resolve directory of the current script and the project root to locate drivers and middleware modules
sys.path.append(PROJECT_DIR)
sys.path.append(os.path.join(PROJECT_DIR, "drivers"))
sys.path.append(os.path.join(PROJECT_DIR, "middleware", "Sniffer"))
sys.path.append(os.path.join(PROJECT_DIR, "middleware", "UCI"))

import argparse
import struct
import time

# Save the real stdout file descriptor before redirecting it
REAL_STDOUT_FD = os.dup(1)

# Redirect standard output (fd 1) to standard error (fd 2) at the OS level.
# This guarantees that any prints, logo dumps, or colorama streams in libraries
# are redirected to stderr and do not corrupt the extcap protocol stream.
os.dup2(2, 1)

# Open a new file object representing the original stdout stream to talk to Wireshark
ORIGINAL_STDOUT = os.fdopen(REAL_STDOUT_FD, 'w')

# A simple log function that writes to the system temp folder to prevent permission/sandbox issues
import tempfile
LOG_FILE_PATH = os.path.join(tempfile.gettempdir(), "forthink_sniffer.log")

def log_to_file(msg):
    try:
        with open(LOG_FILE_PATH, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except Exception:
        pass

# Redefine standard print to write to the log file instead of polluting stderr/stdout
import builtins
original_print = builtins.print

def custom_print(*args, **kwargs):
    file = kwargs.get('file', sys.stdout)
    if file not in (sys.stdout, sys.stderr):
        original_print(*args, **kwargs)
    else:
        msg = " ".join(str(arg) for arg in args)
        log_to_file(msg)

builtins.print = custom_print

try:
    from forthink_uwb_dongle import scan_uwb_dongle_devices, forthink_uwb_dongle
    from nxp_ft4222h import EnumFtdiSpiMode
    from SnifferDevice import SnifferDevice, SnifferParam
    from uci_defs import EnumUciStatus
    
    # Silence console helper logs by redirecting them to the file log
    import console_helper
    console_helper.log_i = lambda info: log_to_file(f"[dbg/I] {info}")
    console_helper.log_d = lambda info: log_to_file(f"[dbg/D] {info}")
    console_helper.log_w = lambda warn: log_to_file(f"[dbg/W] {warn}")
    console_helper.log_p = lambda lg: log_to_file(f"[dbg/P] {lg}")
    
    def log_e_to_stderr(err):
        sys.stderr.write(f"[dbg/E] {err}\n")
    console_helper.log_e = log_e_to_stderr
except Exception as e:
    sys.stderr.write(f"Error importing modules: {e}\n")
    sys.exit(1)


def list_interfaces():
    """Outputs the list of detected sniffer devices to Wireshark."""
    # Write the extcap metadata sentence
    ORIGINAL_STDOUT.write("extcap {version=1.0.0}{display=Forthink UWB Sniffer Extcap}\n")
    
    try:
        devices = scan_uwb_dongle_devices()
        if not devices:
            # Report a single placeholder interface if no device is found
            ORIGINAL_STDOUT.write("interface {value=forthink_uwb_sniffer}{display=Forthink UWB Sniffer}\n")
        else:
            for dev in devices:
                # Interface identifier to support sniffer
                ORIGINAL_STDOUT.write(f"interface {{value=forthink_uwb_sniffer}}{{display=Forthink UWB Sniffer}}\n")
    except Exception as e:
        sys.stderr.write(f"Error scanning devices: {e}\n")
        ORIGINAL_STDOUT.write("interface {value=forthink_uwb_sniffer}{display=Forthink UWB Sniffer (Scan Error)}\n")
    
    ORIGINAL_STDOUT.flush()


def list_dlts(interface):
    """Outputs the supported Link Layer types for the specified interface."""
    # LINKTYPE_IEEE802_15_4_TAP is 283 (IEEE 802.15.4 Wireless PAN with TAP pseudo-header)
    ORIGINAL_STDOUT.write("dlt {number=283}{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 Wireless PAN with TAP}\n")
    ORIGINAL_STDOUT.flush()


def list_config(interface):
    """Outputs the configuration settings for the sniffer interface."""
    # Channel selection: 5, 6, 8, 9. Default is Channel 9.
    ORIGINAL_STDOUT.write("arg {number=0}{call=--channel}{display=Channel}{type=selector}{tooltip=UWB Channel}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=5}{display=Channel 5 (6489.6 MHz)}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=6}{display=Channel 6 (6988.8 MHz)}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=8}{display=Channel 8 (7488.0 MHz)}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=9}{display=Channel 9 (7987.2 MHz)}{default=true}\n")

    # Preamble Code ID selection: 9 to 24. Default is 9.
    ORIGINAL_STDOUT.write("arg {number=1}{call=--preamble-id}{display=Preamble ID}{type=selector}{tooltip=Preamble Code ID (9-24)}\n")
    for p in range(9, 25):
        default_str = "true" if p == 9 else "false"
        ORIGINAL_STDOUT.write(f"value {{arg=1}}{{value={p}}}{{display=Preamble {p}}}{{default={default_str}}}\n")

    # SFD ID selection: 0 or 2. Default is 2.
    ORIGINAL_STDOUT.write("arg {number=2}{call=--sfd-id}{display=SFD ID}{type=selector}{tooltip=SFD ID (0 or 2)}\n")
    ORIGINAL_STDOUT.write("value {arg=2}{value=0}{display=SFD 0}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=2}{value=2}{display=SFD 2}{default=true}\n")

    ORIGINAL_STDOUT.flush()


def capture(interface, fifo, channel, preamble_id, sfd_id):
    """Initializes the sniffer hardware and pipes captured packets to the Wireshark FIFO."""
    target_location = None
    if interface.startswith("forthink_uwb_sniffer_"):
        try:
            target_location = int(interface.split("_")[-1])
        except ValueError:
            pass

    log_to_file("Scanning for UWB dongle devices...")
    try:
        devices = scan_uwb_dongle_devices()
    except Exception as e:
        sys.stderr.write(f"Failed to scan devices: {e}\n")
        sys.exit(1)

    if not devices:
        sys.stderr.write("No UWB dongle devices found. Capture cannot start.\n")
        sys.exit(1)

    selected_dev = None
    if target_location is not None:
        for dev in devices:
            if dev.device_location == target_location:
                selected_dev = dev
                break
        if not selected_dev:
            log_to_file(f"Could not find device at location {target_location}. Falling back to first available device.")

    if not selected_dev:
        selected_dev = devices[0]

    log_to_file(f"Selected device at location: {selected_dev.device_location}")

    # Connect to the UWB Dongle
    try:
        dongle = forthink_uwb_dongle(selected_dev)
        dongle.ft4222_device.open(spi_frequency_hz=1e07, mode=EnumFtdiSpiMode.FTDI_SPI_MODE_SINGLE)
        sniffer_app = SnifferDevice(dongle.ft4222_device)
        
        # Perform device reset
        sniffer_app.device.hard_reset()
        result = sniffer_app.wait_response(timeout_ms=200)
        if result.status is not EnumUciStatus.UCI_STATUS_REBOOT:
            log_to_file(f"Warning: Unexpected reboot status response: {result.status}")

        # Configure sniffer parameter settings
        sniffer_param = SnifferParam(channel=channel)
        sniffer_param.set_sfd_id(sfd_id)
        sniffer_param.set_preamble_id(preamble_id)

        log_to_file(f"Configuring device: Channel={channel}, Preamble ID={preamble_id}, SFD ID={sfd_id}")
        sniffer_app.sniffer_cfg_ranging_app(sniffer_param.channel_id, sniffer_param.tx_power)
        sniffer_app.sniffer_cfg_rx_mode(sniffer_param.preamble_id, sniffer_param.sfd_id)
    except Exception as e:
        sys.stderr.write(f"Failed to initialize sniffer hardware: {e}\n")
        sys.exit(1)

    # Open target FIFO pipe
    try:
        fifo_file = open(fifo, "wb")
    except Exception as e:
        sys.stderr.write(f"Failed to open FIFO pipe at {fifo}: {e}\n")
        sys.exit(1)

    # Write PCAP global header
    try:
        # Global header: magic, major, minor, zone, sigfigs, snaplen, network (DLT 283)
        global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 283)
        fifo_file.write(global_header)
        fifo_file.flush()
    except Exception as e:
        sys.stderr.write(f"Failed to write PCAP global header: {e}\n")
        fifo_file.close()
        sys.exit(1)

    log_to_file("Sniffer active. Capturing packets...")
    try:
        while True:
            try:
                # Capture next received frame from sniffer
                result = sniffer_app.sniffer_start_rx_mode()
                if result.status == EnumUciStatus.UCI_STATUS_OK.value:
                    rx_result = result.uci_result
                    if rx_result.payload and len(rx_result.payload) > 0:
                        t = time.time()
                        sec = int(t)
                        usec = int((t - sec) * 1000000)
                        
                        data = bytes(rx_result.payload)
                        length = len(data)
                        
                        # Build TAP pseudo-header (Type-Length-Value format)
                        # Total size of pseudo-header: 4 (Type 0 header) + 8 (Channel TLV) + 8 (RSSI TLV) = 20 bytes
                        tap_header_len = 20
                        pcap_pseudo_header = struct.pack('<HH', 0, tap_header_len)
                        
                        # Pack Channel TLV (Type 3, Length 3, value: 2-byte channel, 1-byte page)
                        # Packs 8 bytes total using <HHHH (Type, Length, Channel, Page) including 1-byte padding
                        pcap_pseudo_header += struct.pack('<HHHH', 3, 3, channel, 0)
                        
                        # Pack RSSI TLV (Type 1, Length 4, value: 4-byte float)
                        # Packs 8 bytes total using <HHf (Type, Length, RSSI)
                        rssi_val = rx_result.max_overall_rssi if rx_result.max_overall_rssi is not None else 0.0
                        pcap_pseudo_header += struct.pack('<HHf', 1, 4, float(rssi_val))
                        
                        # Pack raw frame into standard PCAP packet structure
                        pcap_length = length + tap_header_len
                        pcap_header = struct.pack('<IIII', sec, usec, pcap_length, pcap_length)
                        fifo_file.write(pcap_header)
                        fifo_file.write(pcap_pseudo_header)
                        fifo_file.write(data)
                        fifo_file.flush()
                        
                        log_to_file(f"Captured {length} bytes packet.")
            except Exception as capture_error:
                log_to_file(f"Error in capture loop iteration: {capture_error}")
                time.sleep(0.1)
    except KeyboardInterrupt:
        log_to_file("Capture stopped by user request.")
    finally:
        log_to_file("Closing device connection...")
        try:
            sniffer_app.device.hard_reset()
            dongle.ft4222_device.close()
        except Exception as close_error:
            log_to_file(f"Error during device shutdown: {close_error}")
        
        try:
            fifo_file.close()
        except Exception:
            pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Forthink UWB Sniffer Extcap Plugin")
    parser.add_argument("--extcap-interfaces", action="store_true", help="List available interfaces")
    parser.add_argument("--extcap-dlts", action="store_true", help="List DLTs for the interface")
    parser.add_argument("--extcap-config", action="store_true", help="List configuration options")
    parser.add_argument("--extcap-interface", type=str, help="Specify interface name")
    parser.add_argument("--extcap-dlt", type=int, help="Specify selected DLT")
    parser.add_argument("--fifo", type=str, help="Path to FIFO pipe for packet stream")
    parser.add_argument("--capture", action="store_true", help="Start capture mode")
    
    # Custom configuration arguments from Wireshark GUI
    parser.add_argument("--channel", type=int, default=9, choices=[5, 6, 8, 9], help="UWB Channel")
    parser.add_argument("--preamble-id", type=int, default=9, choices=list(range(9, 25)), help="Preamble Code ID")
    parser.add_argument("--sfd-id", type=int, default=2, choices=[0, 2], help="SFD ID")

    args, unknown = parser.parse_known_args()

    if args.extcap_interfaces:
        list_interfaces()
    elif args.extcap_config:
        list_config(args.extcap_interface)
    elif args.extcap_dlts:
        list_dlts(args.extcap_interface)
    elif args.capture:
        if not args.fifo:
            sys.stderr.write("Error: --fifo parameter is required for capture.\n")
            sys.exit(1)
        capture(args.extcap_interface, args.fifo, args.channel, args.preamble_id, args.sfd_id)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)
