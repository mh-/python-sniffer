#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
forthink_fast_sniffer_extcap.py  —  "superfast" UWB sniffer extcap plugin

Difference from forthink_sniffer_extcap.py:
  Instead of the slow per-packet START_RX_MODE round-trip, this variant
  uploads 5 firmware memory patches extracted from the Windows USB trace and
  then issues SNIFFER_STORE_RADIO_SETTINGS which commits them AND arms the chip
  for fully autonomous continuous RX.  The host then passively receives UCI NTF
  messages as packets arrive — no re-arming per packet.

  This mirrors exactly what the Windows sniffer tool does and enables capturing
  fast consecutive UWB packets (≥5 ms cadence) that the original Python loop
  silently misses.

Limitations:
  - The firmware patches are hard-coded for Ch9 / Preamble 9 / SFD 2.
    Until a per-channel patch set is extracted or generated, channel / preamble /
    SFD selection in the Wireshark UI is accepted but ignored.
"""

import os
import sys

# Auto-reexecute using virtualenv if available locally
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
if os.name == 'nt':
    VENV_PYTHON = os.path.join(PROJECT_DIR, "venv", "Scripts", "python.exe")
else:
    VENV_PYTHON = os.path.join(PROJECT_DIR, "venv", "bin", "python3")

if os.path.exists(VENV_PYTHON) and os.path.realpath(sys.executable) != os.path.realpath(VENV_PYTHON):
    try:
        os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)
    except OSError:
        pass # Fallback to current python if execv fails (e.g. copied mac venv to windows)

# Resolve module search paths
sys.path.append(PROJECT_DIR)
sys.path.append(os.path.join(PROJECT_DIR, "drivers"))
sys.path.append(os.path.join(PROJECT_DIR, "middleware", "Sniffer"))
sys.path.append(os.path.join(PROJECT_DIR, "middleware", "UCI"))

import argparse
import struct
import math
import time

# ---------------------------------------------------------------------------
# Firmware patch blobs — exact bytes from Windows USB trace (usbtracewindows.pcapng).
#
# These are complete UCI frames (4-byte UCI header + payload) for:
#   SNIFFER_SET_BUFFER  (GID=0x0E, OID=0x12)
#   SNIFFER_STORE_RADIO_SETTINGS (GID=0x0E, OID=0x10)
#
# The patches write Ch9 / Preamble 9 / SFD 2 radio configuration directly into
# chip memory.  SNIFFER_STORE_RADIO_SETTINGS commits the patches AND starts
# autonomous continuous RX — no SNIFFER_START_RX_MODE (0x2E 0x1B) is needed.
#
# Sequence extracted from frames 94244–95145 of usbtracewindows.pcapng:
#   Group 1: 3 SET_BUFFER patches  →  STORE_RADIO_SETTINGS  (commit)
#   Group 2: 2 SET_BUFFER patches  →  STORE_RADIO_SETTINGS  (commit + arm RX)
# ---------------------------------------------------------------------------

# Group 1 — three SET_BUFFER patches (exact bytes from usbtracewindows.pcapng frames 94244/94374/94529)
_PATCH_1A = bytes.fromhex("2e1200fd00000c0000000002000001000000881300051014740001000000ff7f008000005645047c1c40020535047e0000008f981900047000001010140cc400060008265400040c04041c07041c07030000000000007e03020019021902000300000100000007000f00ff03ff03002e030010001000100050036008010200030406060638040a0000002200000009001100000000000008080f070102000008080f0f05070009001100310000000808080801010203080808080405070900000000000000000000000000000000000000b7000000000000000000000000000000ff18020807100e00000000330a00000603000001006f000000290001010400fe")  # 257 bytes
_PATCH_1B = bytes.fromhex("2e1200fdfb0021000000240400260c010c0501ffff590000201100070201004a013000012f00000000000000cd800210c8c202102210100d00826212cd952f1cc9d6de58ba33d51f0886e20600eb60040000000000007f7f7f7f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000ff03000000005e4f080000000008c2d3a406daf1a265796141008a98364e00000000791f0f72ff2cf5328a98364e000000001cfef8070070470000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")  # 257 bytes
_PATCH_1C = bytes.fromhex("2e120014f6010000000000000000000000000000002c0400")

# SNIFFER_STORE_RADIO_SETTINGS — commits patches and triggers RX arming
_PATCH_STORE_RADIO = bytes.fromhex("2e1000020000")

# Group 2 — two SET_BUFFER patches (frames 94796/94939)
_PATCH_2A = bytes.fromhex("2e1200fd00001c000000000100000b1f3a4e4d3612f3e6edfc070702fbfafc00010100feff0000000000000000000b1f3a4e4d3612f3e6edfc070702fbfafc00010100feff0000000000000000000b1f3a4e4d3612f3e6edfc070702fbfafc00010100feff0000000000000000000808000008013300950d000083eb3f0041c03c7c44701701d440303c473c5714d0045353c141c4d47d0010000730031f000000007fdf000000000000000000000000000000000000000000000000000000000000030000002e400000080000000a0080011400803f1200f802e873000024080000cd0c00001d0113001b00000000000000007047000000000000000000000000")  # 257 bytes
_PATCH_2B = bytes.fromhex("2e12000ffb00000000000000000000002c0400")

_PATCH_GROUP_1 = [_PATCH_1A, _PATCH_1B, _PATCH_1C]
_PATCH_GROUP_2 = [_PATCH_2A, _PATCH_2B]

# ---------------------------------------------------------------------------
# Stdout / logging plumbing (identical to the original extcap script)
# ---------------------------------------------------------------------------

# Save the real stdout file descriptor before redirecting it
REAL_STDOUT_FD = os.dup(1)

# Redirect standard output (fd 1) to standard error (fd 2) at the OS level.
# This guarantees that any prints or library output do not corrupt the extcap stream.
os.dup2(2, 1)

# Open a new file object representing the original stdout stream to talk to Wireshark
ORIGINAL_STDOUT = os.fdopen(REAL_STDOUT_FD, 'w')

import tempfile
LOG_FILE_PATH = os.path.join(tempfile.gettempdir(), "forthink_fast_sniffer.log")
ENABLE_LOGGING = False  # Set to False to disable all disk logging

def log_to_file(msg):
    if not ENABLE_LOGGING:
        return
    try:
        with open(LOG_FILE_PATH, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except Exception:
        pass

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
    from uci_defs import EnumUciStatus, EnumUciGid, EnumSnifferOid, EnumUciMessageType
    from uci_message import uci_sniffer_start_rx_mode_rsp_callback, UciMessage
    from uci_sniffer_rx_rsp import SnifferRxResult

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


# ---------------------------------------------------------------------------
# Extcap protocol handlers
# ---------------------------------------------------------------------------

def list_interfaces():
    """Outputs the list of detected sniffer devices to Wireshark."""
    ORIGINAL_STDOUT.write("extcap {version=1.0.0}{display=Forthink Fast UWB Sniffer Extcap}\n")
    try:
        devices = scan_uwb_dongle_devices()
        if not devices:
            ORIGINAL_STDOUT.write(
                "interface {value=forthink_fast_uwb_sniffer}"
                "{display=Forthink UWB Sniffer (Fast/Continuous)}\n"
            )
        else:
            for dev in devices:
                ORIGINAL_STDOUT.write(
                    "interface {value=forthink_fast_uwb_sniffer}"
                    "{display=Forthink UWB Sniffer (Fast/Continuous)}\n"
                )
    except Exception as e:
        sys.stderr.write(f"Error scanning devices: {e}\n")
        ORIGINAL_STDOUT.write(
            "interface {value=forthink_fast_uwb_sniffer}"
            "{display=Forthink UWB Sniffer Fast (Scan Error)}\n"
        )
    ORIGINAL_STDOUT.flush()


def list_dlts(interface):
    """Outputs the supported Link Layer types."""
    # LINKTYPE_IEEE802_15_4_TAP = 283
    ORIGINAL_STDOUT.write(
        "dlt {number=283}{name=IEEE802_15_4_TAP}"
        "{display=IEEE 802.15.4 Wireless PAN with TAP}\n"
    )
    ORIGINAL_STDOUT.flush()


def list_config(interface):
    """Outputs the configuration settings."""
    # Channel selection: 5, 6, 8, 9. Default is Channel 9.
    ORIGINAL_STDOUT.write("arg {number=0}{call=--channel}{display=Channel}{type=selector}{tooltip=UWB Channel (Ch9 recommended; patches are fixed for Ch9/P9/SFD2)}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=5}{display=Channel 5 (6489.6 MHz)}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=6}{display=Channel 6 (6988.8 MHz)}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=8}{display=Channel 8 (7488.0 MHz)}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=0}{value=9}{display=Channel 9 (7987.2 MHz)}{default=true}\n")

    # Preamble Code ID selection: 9 to 24. Default is 9.
    ORIGINAL_STDOUT.write("arg {number=1}{call=--preamble-id}{display=Preamble ID}{type=selector}{tooltip=Preamble Code ID (patches fixed for Preamble 9)}\n")
    for p in range(9, 25):
        default_str = "true" if p == 9 else "false"
        ORIGINAL_STDOUT.write(f"value {{arg=1}}{{value={p}}}{{display=Preamble {p}}}{{default={default_str}}}\n")

    # SFD ID selection: 0 or 2. Default is 2.
    ORIGINAL_STDOUT.write("arg {number=2}{call=--sfd-id}{display=SFD ID}{type=selector}{tooltip=SFD ID (patches fixed for SFD 2)}\n")
    ORIGINAL_STDOUT.write("value {arg=2}{value=0}{display=SFD 0}{default=false}\n")
    ORIGINAL_STDOUT.write("value {arg=2}{value=2}{display=SFD 2}{default=true}\n")

    ORIGINAL_STDOUT.flush()


def _send_patch_and_wait(device, patch_bytes, label):
    """Transmit a single UCI patch command and read back the response."""
    device.transmit_uci_command(list(patch_bytes))
    # The Windows tool reads exactly the payload length without the 2-byte CRC at the end
    resp = device.receive_uci_message(timeout_ms=500, crc_enable=False)
    hex_msg = bytes(resp.msg_buffer).hex() if resp.msg_buffer else "None"
    log_to_file(f"  {label}: port_status={resp.status.name if hasattr(resp.status, 'name') else resp.status} msg={hex_msg}")
    return resp


def capture(interface, fifo, channel, preamble_id, sfd_id):
    """Initialize hardware with Windows firmware patches and stream captured packets."""
    target_location = None
    if interface.startswith("forthink_fast_uwb_sniffer_"):
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
            log_to_file(f"Could not find device at location {target_location}. Falling back to first device.")

    if not selected_dev:
        selected_dev = devices[0]

    log_to_file(f"Selected device at location: {selected_dev.device_location}")

    # -----------------------------------------------------------------------
    # Hardware initialization
    # -----------------------------------------------------------------------
    try:
        dongle = forthink_uwb_dongle(selected_dev)
        dongle.ft4222_device.open(spi_frequency_hz=1e07, mode=EnumFtdiSpiMode.FTDI_SPI_MODE_SINGLE)
        sniffer_app = SnifferDevice(dongle.ft4222_device)
        device = sniffer_app.device

        # Register sniffer start RX notification callback
        sniffer_app.register_notification_callback(
            EnumUciGid.UWB_SNIFFER_GID.value,
            EnumSnifferOid.SNIFFER_START_RX_MODE_OID.value,
            uci_sniffer_start_rx_mode_rsp_callback
        )

        # Hard-reset the chip and wait for the boot NTF
        device.hard_reset()
        boot_resp = sniffer_app.wait_response(timeout_ms=500)
        if boot_resp.status is not EnumUciStatus.UCI_STATUS_REBOOT:
            log_to_file(f"Warning: unexpected reboot status: {boot_resp.status}")


        # Upload patch group 1
        log_to_file(f"Uploading firmware patch group 1 for SFD {sfd_id} ...")
        
        patch_1A = bytearray(_PATCH_1A)
        if sfd_id == 0:
            patch_1A[208] = 0x00
            patch_1A[209] = 0x88
            patch_1A[224] = 0x00
            patch_1A[225] = 0x9a
            patch_1A[226] = 0x10
            patch_1A[227] = 0x02
            patch_1A[228] = 0x04
            patch_1A[229] = 0x07
        elif sfd_id == 2:
            patch_1A[208] = 0x00
            patch_1A[209] = 0xb7
            patch_1A[224] = 0x00
            patch_1A[225] = 0xff
            patch_1A[226] = 0x18
            patch_1A[227] = 0x02
            patch_1A[228] = 0x08
            patch_1A[229] = 0x07
            
        _send_patch_and_wait(device, bytes(patch_1A), "patch_1A")
        _send_patch_and_wait(device, _PATCH_1B, "patch_1B")
        _send_patch_and_wait(device, _PATCH_1C, "patch_1C")

        log_to_file("SNIFFER_STORE_RADIO_SETTINGS — committing group 1 ...")
        _send_patch_and_wait(device, _PATCH_STORE_RADIO, "store_radio_1")

        # Upload patch group 2
        log_to_file("Uploading firmware patch group 2 ...")
        
        patch_2A = bytearray(_PATCH_2A)
        if sfd_id == 0:
            patch_2A[162] = 0xc4
            patch_2A[163] = 0xc1
        elif sfd_id == 2:
            patch_2A[162] = 0x7f
            patch_2A[163] = 0xdf
            
        _send_patch_and_wait(device, bytes(patch_2A), "patch_2A")
        _send_patch_and_wait(device, _PATCH_2B, "patch_2B")

        # Commit group 2 — this also arms the chip for autonomous continuous RX
        log_to_file("SNIFFER_STORE_RADIO_SETTINGS — committing group 2 (arms RX) ...")
        _send_patch_and_wait(device, _PATCH_STORE_RADIO, "store_radio_2")

        # 1. CFG_RANGING_APP (2E 28) - Sets the Center Frequency!
        if channel == 5:
            freq_hz = 6489600
        elif channel == 6:
            freq_hz = 6988800
        elif channel == 8:
            freq_hz = 7488000
        elif channel == 9:
            freq_hz = 7987200
        else:
            freq_hz = 7987200
            
        freq_reg = int(freq_hz / 256)
        # Payload format: 0x00 (1 byte), Center Freq (2 bytes), then hardcoded params (11 bytes)
        payload_2e28 = bytes([0x00]) + struct.pack("<H", freq_reg) + bytes.fromhex("0000500064003800ff0001")
        cfg_ranging_app = bytes([0x2e, 0x28, 0x00, len(payload_2e28)]) + payload_2e28
        
        log_to_file(f"Sending CFG_RANGING_APP for Channel {channel} ({freq_hz/1000} MHz) ...")
        _send_patch_and_wait(device, cfg_ranging_app, "cfg_ranging_app")
        
        # 2. CFG_RX_MODE (2E 1A) - Sets the Preamble ID!
        preamble_index = preamble_id - 8
        radio = 0x0C # Hardcoded 12 for now (from Windows trace), might need to adjust based on SFD later
        sts_offset = 0
        toa_algorithm = 1
        rx_delay = 0
        timeout = 0x00FFFFFF
        rx_cycles = 1
        cipher_mode = 0xFF
        xtal_temp_comp = 1
        
        payload_2e1a = struct.pack('<BBBBHIBBB', radio, preamble_index, sts_offset,
                           toa_algorithm, rx_delay, timeout, rx_cycles,
                           cipher_mode, xtal_temp_comp)
        
        cfg_rx_mode = bytes([0x2e, 0x1a, 0x00, len(payload_2e1a)]) + payload_2e1a
        
        log_to_file(f"Sending CFG_RX_MODE for Preamble ID {preamble_id} (Index {preamble_index}) ...")
        _send_patch_and_wait(device, cfg_rx_mode, "cfg_rx_mode")
        
        # 3. 2A 3A
        cmd_2a3a = bytes.fromhex("2a3a00020001")
        log_to_file("Sending unknown 2A 3A command ...")
        _send_patch_and_wait(device, cmd_2a3a, "cmd_2a3a")

        log_to_file("Chip armed for autonomous continuous RX (Ch9/Preamble9/SFD2).")
    except Exception as e:
        sys.stderr.write(f"Failed to initialize sniffer hardware: {e}\n")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Open FIFO and write PCAP global header
    # -----------------------------------------------------------------------
    try:
        fifo_file = open(fifo, "wb")
    except Exception as e:
        sys.stderr.write(f"Failed to open FIFO pipe at {fifo}: {e}\n")
        sys.exit(1)

    try:
        # PCAP global header: magic, major, minor, zone, sigfigs, snaplen, network (DLT 283)
        global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 283)
        fifo_file.write(global_header)
        fifo_file.flush()
    except Exception as e:
        sys.stderr.write(f"Failed to write PCAP global header: {e}\n")
        fifo_file.close()
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Passive capture loop — chip signals packets via INT_N; we just receive
    # -----------------------------------------------------------------------
    log_to_file("Passive capture loop started.  Waiting for UCI NTF messages ...")
    packet_count = 0
    try:
        while True:
            try:
                # Use receive_uci_message directly instead of wait_response, because
                # wait_response will loop and swallow NOTIFICATION messages while waiting
                # for a RESPONSE.
                raw_result = sniffer_app.device.receive_uci_message(timeout_ms=1000, crc_enable=False)

                if raw_result.status.value == 1 and raw_result.msg_buffer:
                    log_to_file(f"Got raw message: {bytes(raw_result.msg_buffer).hex()}")
                    msg = UciMessage.from_bytes(raw_result.msg_buffer)
                    if msg and msg.message_type == EnumUciMessageType.UCI_MT_NOTIFICATION:
                        data = None
                        rssi = 0.0
                        # 1. Check for legacy SNIFFER_START_RX_MODE notifications (0x6E 0x1B)
                        if msg.gid == EnumUciGid.UWB_SNIFFER_GID.value and msg.oid == EnumSnifferOid.SNIFFER_START_RX_MODE_OID.value:
                            rx_result = SnifferRxResult.from_bytes(msg.payload)
                            if (rx_result is not None and hasattr(rx_result, 'payload') and rx_result.payload and len(rx_result.payload) > 0):
                                data = bytes(rx_result.payload)
                                rssi = rx_result.max_overall_rssi if rx_result.max_overall_rssi is not None else 0.0
                                packet_count += 1
                                log_to_file(f"Captured legacy packet {packet_count}: {len(data)} bytes")

                        elif msg.gid == 0x0A and msg.oid == 0x3A:
                            if len(msg.payload) >= 56:
                                # The actual 802.15.4 MAC payload starts at offset 56
                                data = bytes(msg.payload[56:])
                                
                                # Multiplication by 8.9718e-8, on 4 bytes that are encoded in Word-Swapped Little-Endian. 
                                # They start 11 bytes before the payload.
                                # The payload starts at 56, so 56 - 11 = 45.
                                if len(msg.payload) >= 49:
                                    b = msg.payload[45:49]
                                    # Word-Swapped Little-Endian: swap the two 16-bit words
                                    swapped = bytes([b[2], b[3], b[0], b[1]])
                                    raw_val = struct.unpack("<i", swapped)[0]
                                    rssi = raw_val * 8.9718e-8
                                else:
                                    rssi = 0.0
                                
                                packet_count += 1
                                log_to_file(f"Captured fast packet {packet_count}: {len(data)} bytes, RSSI: {rssi:.2f} dBm")


                        # Write to PCAP if we have data
                        if data is not None and len(data) > 0:
                            t = time.time()
                            sec = int(t)
                            usec = int((t - sec) * 1_000_000)
                            length = len(data)

                            # IEEE 802.15.4 TAP pseudo-header
                            # Total: 4 (header) + 8 (Channel TLV) + 8 (RSSI TLV) = 20 bytes
                            tap_header_len = 20
                            pcap_pseudo_header = struct.pack('<HH', 0, tap_header_len)

                            # Channel TLV: Type=3, Length=3, channel (2B LE), page=0 (1B + 1B pad)
                            pcap_pseudo_header += struct.pack('<HHHH', 3, 3, channel, 0)

                            # RSSI TLV: Type=1, Length=4, RSSI as IEEE 754 float
                            pcap_pseudo_header += struct.pack('<HHf', 1, 4, float(rssi))

                            # PCAP packet record
                            pcap_length = length + tap_header_len
                            pcap_header = struct.pack('<IIII', sec, usec, pcap_length, pcap_length)
                            fifo_file.write(pcap_header)
                            fifo_file.write(pcap_pseudo_header)
                            fifo_file.write(data)
                            fifo_file.flush()

                # On timeout or non-OK status, loop immediately — chip stays in RX.
            except Exception as capture_error:
                import traceback
                log_to_file(f"Error in capture loop: {capture_error}\n{traceback.format_exc()}")
                time.sleep(0.05)

    except KeyboardInterrupt:
        log_to_file("Capture stopped by user.")
    except Exception as general_error:
        import traceback
        log_to_file(f"Fatal error in capture script: {general_error}\n{traceback.format_exc()}")
        sys.stderr.write(f"Fatal error: {general_error}\n")
    finally:
        log_to_file("Closing device connection ...")
        try:
            if 'device' in locals() and device is not None:
                device.hard_reset()
            if 'dongle' in locals() and dongle is not None:
                dongle.ft4222_device.close()
        except Exception as close_error:
            log_to_file(f"Error during device shutdown: {close_error}")
        try:
            if 'fifo_file' in locals() and fifo_file is not None:
                fifo_file.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Forthink UWB Sniffer Fast Extcap Plugin (Windows-compatible patch init)"
    )
    parser.add_argument("--extcap-interfaces", action="store_true", help="List available interfaces")
    parser.add_argument("--extcap-dlts", action="store_true", help="List DLTs for the interface")
    parser.add_argument("--extcap-config", action="store_true", help="List configuration options")
    parser.add_argument("--extcap-interface", type=str, help="Specify interface name")
    parser.add_argument("--extcap-dlt", type=int, help="Specify selected DLT")
    parser.add_argument("--fifo", type=str, help="Path to FIFO pipe for packet stream")
    parser.add_argument("--capture", action="store_true", help="Start capture mode")

    # Configuration arguments (forwarded from Wireshark UI)
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
