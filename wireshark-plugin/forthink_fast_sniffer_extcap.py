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
VENV_PYTHON = os.path.join(PROJECT_DIR, "venv", "bin", "python3")
if os.path.exists(VENV_PYTHON) and os.path.realpath(sys.executable) != os.path.realpath(VENV_PYTHON):
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

# Resolve module search paths
sys.path.append(PROJECT_DIR)
sys.path.append(os.path.join(PROJECT_DIR, "drivers"))
sys.path.append(os.path.join(PROJECT_DIR, "middleware", "Sniffer"))
sys.path.append(os.path.join(PROJECT_DIR, "middleware", "UCI"))

import argparse
import struct
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

def log_to_file(msg):
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
    from uci_defs import EnumUciStatus

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
    device.transmit_uci_command(patch_bytes)
    resp = device.receive_uci_message(timeout_ms=500)
    log_to_file(f"  {label}: resp.status={resp.status}")
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

        # Hard-reset the chip and wait for the boot NTF
        device.hard_reset()
        boot_resp = sniffer_app.wait_response(timeout_ms=500)
        if boot_resp.status is not EnumUciStatus.UCI_STATUS_REBOOT:
            log_to_file(f"Warning: unexpected reboot status: {boot_resp.status}")

        # Note: the patches are hard-coded for Ch9/Preamble9/SFD2.
        # Log a warning if the user selected different settings.
        if channel != 9 or preamble_id != 9 or sfd_id != 2:
            log_to_file(
                f"WARNING: firmware patches are fixed for Ch9/P9/SFD2.  "
                f"Requested Ch{channel}/P{preamble_id}/SFD{sfd_id} will be ignored."
            )
            sys.stderr.write(
                f"[forthink_fast] WARNING: firmware patches are fixed for Ch9/Preamble9/SFD2.  "
                f"Ch{channel}/P{preamble_id}/SFD{sfd_id} ignored.\n"
            )

        # Upload patch group 1
        log_to_file("Uploading firmware patch group 1 ...")
        _send_patch_and_wait(device, _PATCH_1A, "patch_1A")
        _send_patch_and_wait(device, _PATCH_1B, "patch_1B")
        _send_patch_and_wait(device, _PATCH_1C, "patch_1C")

        # Commit group 1
        log_to_file("SNIFFER_STORE_RADIO_SETTINGS — committing group 1 ...")
        _send_patch_and_wait(device, _PATCH_STORE_RADIO, "store_radio_1")

        # Upload patch group 2
        log_to_file("Uploading firmware patch group 2 ...")
        _send_patch_and_wait(device, _PATCH_2A, "patch_2A")
        _send_patch_and_wait(device, _PATCH_2B, "patch_2B")

        # Commit group 2 — this also arms the chip for autonomous continuous RX
        log_to_file("SNIFFER_STORE_RADIO_SETTINGS — committing group 2 (arms RX) ...")
        _send_patch_and_wait(device, _PATCH_STORE_RADIO, "store_radio_2")

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
    try:
        while True:
            try:
                # wait_response() drives receive_uci_message() which:
                #   1. Blocks until INT_N goes LOW (chip has data ready)
                #   2. Pulls CS_N LOW, reads 5-byte UCI header, then payload
                #   3. Releases CS_N HIGH and waits for INT_N to go HIGH
                # No re-arming command is sent — the chip is continuously receiving.
                result = sniffer_app.wait_response(timeout_ms=17000)

                if result.status == EnumUciStatus.UCI_STATUS_OK:
                    rx_result = result.uci_result
                    if (rx_result is not None
                            and hasattr(rx_result, 'payload')
                            and rx_result.payload
                            and len(rx_result.payload) > 0):

                        t = time.time()
                        sec = int(t)
                        usec = int((t - sec) * 1_000_000)

                        data = bytes(rx_result.payload)
                        length = len(data)

                        # IEEE 802.15.4 TAP pseudo-header
                        # Total: 4 (header) + 8 (Channel TLV) + 8 (RSSI TLV) = 20 bytes
                        tap_header_len = 20
                        pcap_pseudo_header = struct.pack('<HH', 0, tap_header_len)

                        # Channel TLV: Type=3, Length=3, channel (2B LE), page=0 (1B + 1B pad)
                        pcap_pseudo_header += struct.pack('<HHHH', 3, 3, channel, 0)

                        # RSSI TLV: Type=1, Length=4, RSSI as IEEE 754 float
                        rssi_val = (rx_result.max_overall_rssi
                                    if rx_result.max_overall_rssi is not None
                                    else 0.0)
                        pcap_pseudo_header += struct.pack('<HHf', 1, 4, float(rssi_val))

                        # PCAP packet record
                        pcap_length = length + tap_header_len
                        pcap_header = struct.pack('<IIII', sec, usec, pcap_length, pcap_length)
                        fifo_file.write(pcap_header)
                        fifo_file.write(pcap_pseudo_header)
                        fifo_file.write(data)
                        fifo_file.flush()

                        log_to_file(f"Captured {length} bytes.")

                # On timeout or non-OK status, loop immediately — chip stays in RX.
            except Exception as capture_error:
                log_to_file(f"Error in capture loop: {capture_error}")
                time.sleep(0.05)

    except KeyboardInterrupt:
        log_to_file("Capture stopped by user.")
    finally:
        log_to_file("Closing device connection ...")
        try:
            device.hard_reset()
            dongle.ft4222_device.close()
        except Exception as close_error:
            log_to_file(f"Error during device shutdown: {close_error}")
        try:
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
