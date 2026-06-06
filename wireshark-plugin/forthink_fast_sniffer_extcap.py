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

import signal
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
    from nxp_ft4222h import EnumFtdiSpiMode, Ft4222hDevice
    from SnifferDevice import SnifferDevice, SnifferParam
    from uci_defs import EnumUciStatus
    from uci_port import UCIDevice, UCIPortResult, EnumUCIPortStatus
    from uci_message import UciMessage, EnumUciMessageType
    from uci_defs import EnumUciGid, EnumSnifferOid
    
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

def compile_fast_capture():
    src_file = os.path.join(SCRIPT_DIR, "fast_usb_capture.cpp")
    bin_file = os.path.join(SCRIPT_DIR, "fast_usb_capture")
    
    if not os.path.exists(bin_file) or os.path.getmtime(src_file) > os.path.getmtime(bin_file):
        log_to_file("Compiling fast_usb_capture.cpp...")
        import subprocess
        try:
            subprocess.run(["clang++", "-O3", "-std=c++11", src_file, "-o", bin_file], check=True)
            log_to_file("Compilation successful.")
        except subprocess.CalledProcessError as e:
            sys.stderr.write(f"Failed to compile fast_usb_capture.cpp: {e}\n")
            sys.exit(1)

class ProxyFt4222hDevice(Ft4222hDevice):
    def __init__(self, index, device_location, bD5=True):
        self.device_index = index
        self.device_location = device_location
        self.is_ncj29d5 = bD5
        self.proc = None
        
    def _send_cmd(self, cmd):
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise Exception("Process not initialized")
        log_to_file(f"Proxy sending: {cmd}")
        self.proc.stdin.write((cmd + "\n").encode())
        self.proc.stdin.flush()
        resp = self.proc.stdout.readline().decode().strip()
        log_to_file(f"Proxy received: {resp}")
        if resp.startswith("ERR"):
            raise Exception(f"C++ Proxy Error: {resp} (Cmd: {cmd})")
        return resp

    def open(self, spi_frequency_hz=1e07, mode=0):
        import ft4222
        bin_file = os.path.join(SCRIPT_DIR, "fast_usb_capture")
        dylib_path = ft4222.__file__.replace("__init__.py", "libft4222.dylib")
        
        import subprocess
        log_to_file(f"Starting proxy: bin={bin_file}, dylib={dylib_path}")
        self.err_log = open(os.path.join(SCRIPT_DIR, "cpp_proxy.log"), "w")
        self.proc = subprocess.Popen([bin_file, dylib_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err_log)
        
        self._send_cmd(f"OPEN {self.device_location}")
        self._send_cmd(f"OPEN_GPIO {self.device_location + 1}")
        
        clk, div = self.get_spi_clock_divider(spi_frequency_hz)
        self._send_cmd(f"SET_CLOCK {clk}")
        self._send_cmd(f"SPI_INIT 1 {div} 1 0 1")
        self._send_cmd(f"SPI_DRIVING 0 0 0") 
        self._send_cmd(f"SET_TIMEOUTS 100 100")
        
        self._send_cmd(f"GPIO_INIT 0 1 0 1") 
        self._send_cmd(f"SET_SUSPEND_OUT 0")
        self._send_cmd(f"SET_WAKE_UP_INTERRUPT 0")
        
        self.set_cs_n(True)
        self.set_rst_n(True)
        self._send_cmd(f"SPI_RESET")
        return self

    def close(self) -> None:
        if self.proc:
            try:
                if self.proc.poll() is None:
                    self._send_cmd("CLOSE")
                    self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            finally:
                for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                    if stream:
                        try:
                            stream.close()
                        except Exception:
                            pass
                if hasattr(self, 'err_log') and self.err_log:
                    try:
                        self.err_log.close()
                    except Exception:
                        pass

    def get_spi_clock_divider(self, requested_spi_frequency_hz):
        if requested_spi_frequency_hz == 1.0e07:
            return 3, 3 
        return 3, 4 

    def set_rst_n(self, gpio_level):
        val = 1 if gpio_level else 0
        self._send_cmd(f"GPIO_WRITE 0 {val}")

    def set_cs_n(self, gpio_level):
        val = 1 if gpio_level else 0
        self._send_cmd(f"GPIO_WRITE 2 {val}")

    def get_rdy_n(self):
        resp = self._send_cmd(f"GPIO_READ 1")
        return resp == "VAL 1"

    def get_int_n(self):
        resp = self._send_cmd(f"GPIO_READ 3")
        return resp == "VAL 1"

    def hard_reset(self):
        self.set_rst_n(False)
        time.sleep(0.1)
        self.set_rst_n(True)
        time.sleep(0.1)
        
    def wait_for_gpio(self, pin, gpio_level, timeout_ms=0):
        poll_func = self.get_rdy_n if pin == 0 else self.get_int_n
        timeout_sec = timeout_ms / 1000.0
        start = time.perf_counter()
        while True:
            if timeout_ms != 0 and time.perf_counter() - start > timeout_sec:
                return EnumUCIPortStatus.UCI_PORT_STATUS_ERR_TIMEOUT
            if poll_func() == gpio_level:
                return EnumUCIPortStatus.UCI_PORT_STATUS_OK
            time.sleep(0.01)

    def transmit_uci_command(self, input_command, append_crc=False, timeout_ms=0):
        command = list(input_command)
        if append_crc:
            import nxp_crc
            crc = nxp_crc.calculate_crc(frame=command)
            command += list(crc.to_bytes(2, 'little'))
            
        if not self.get_int_n():
            self.receive_uci_message(timeout_ms)
            self.wait_for_gpio(1, True, timeout_ms=10)
            
        self.set_cs_n(False)
        status = self.wait_for_gpio(0, False, timeout_ms)
        if status != EnumUCIPortStatus.UCI_PORT_STATUS_OK:
            return UCIPortResult(status, [], False)
            
        hex_data = bytes(command).hex()
        resp = self._send_cmd(f"SPI_XFER 1 {hex_data}")
        rx_hex = resp[3:] 
        target_miso = bytes.fromhex(rx_hex)
        
        self.set_cs_n(True)
        return UCIPortResult(EnumUCIPortStatus.UCI_PORT_STATUS_OK, list(target_miso), False)

    def receive_uci_message(self, timeout_ms=400, crc_enable=True):
        status = self.wait_for_gpio(1, False, timeout_ms)
        if status != EnumUCIPortStatus.UCI_PORT_STATUS_OK:
            return UCIPortResult(status, [], False)
            
        self.set_cs_n(False)
        
        if self.is_ncj29d5:
            hex_data = ("00" * 5)
            resp = self._send_cmd(f"SPI_XFER 0 {hex_data}")
            header = list(bytes.fromhex(resp[3:]))
            payload_length = header[4] + (header[3] << 8)
            pad = 2 if crc_enable else 0
            hex_data = ("00" * (payload_length + pad))
            resp = self._send_cmd(f"SPI_XFER 1 {hex_data}")
            payload = list(bytes.fromhex(resp[3:]))
            uci_frame = header[1:] + payload
        else:
            hex_data = ("00" * 4)
            resp = self._send_cmd(f"SPI_XFER 0 {hex_data}")
            header = list(bytes.fromhex(resp[3:]))
            payload_length = header[3] + (header[2] << 8)
            pad = 2 if crc_enable else 0
            hex_data = ("00" * (payload_length + pad))
            resp = self._send_cmd(f"SPI_XFER 1 {hex_data}")
            payload = list(bytes.fromhex(resp[3:]))
            uci_frame = header + payload

        self.wait_for_gpio(1, True, timeout_ms)
        self.set_cs_n(True)
        
        is_crc_valid = False
        if crc_enable and len(uci_frame) >= 2:
            import nxp_crc
            received_crc = uci_frame[-2] | (uci_frame[-1] << 8)
            is_crc_valid = nxp_crc.is_crc_valid(uci_frame[:-2], received_crc)
            
        return UCIPortResult(EnumUCIPortStatus.UCI_PORT_STATUS_OK, list(uci_frame), is_crc_valid)


def list_interfaces():
    """Outputs the list of detected sniffer devices to Wireshark."""
    # Write the extcap metadata sentence
    ORIGINAL_STDOUT.write("extcap {version=1.0.0}{display=Forthink Fast UWB Sniffer Extcap}\n")
    
    try:
        devices = scan_uwb_dongle_devices()
        if not devices:
            sys.stderr.write("No FT4222 devices found.\n")
            # Report a single placeholder interface if no device is found
            ORIGINAL_STDOUT.write("interface {value=forthink_fast_uwb_sniffer}{display=Forthink Fast UWB Sniffer}\n")
        else:
            for dev in devices:
                ORIGINAL_STDOUT.write("interface {value=forthink_fast_uwb_sniffer}{display=Forthink Fast UWB Sniffer}\n")
    except Exception as e:
        sys.stderr.write(f"Error scanning devices: {e}\n")
        ORIGINAL_STDOUT.write("interface {value=forthink_fast_uwb_sniffer}{display=Forthink Fast UWB Sniffer (Scan Error)}\n")
    
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

def capture(interface, fifo, channel, preamble_id, sfd_id):
    """Initializes the sniffer hardware and pipes captured packets to the Wireshark FIFO."""
    target_index = None
    if interface.startswith("forthink_fast_uwb_sniffer_"):
        try:
            target_index = int(interface.split("_")[-1])
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
    if target_index is not None and target_index < len(devices):
        selected_dev = devices[target_index]
    else:
        if target_index is not None:
            log_to_file(f"Could not find device at index {target_index}. Falling back to first available device.")
        selected_dev = devices[0]

    log_to_file(f"Selected device at location: {selected_dev.device_location}")

    compile_fast_capture()

    # Connect to the UWB Dongle using the Proxy device
    try:
        dongle = forthink_uwb_dongle(selected_dev)
        dongle.ft4222_device = ProxyFt4222hDevice(selected_dev.device_index, selected_dev.device_location, bD5=dongle.ft4222_device.is_ncj29d5)
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

    log_to_file("Sniffer active. Handing over capture to C++...")
    try:
        tap_header_len = 20
        pcap_pseudo_header = struct.pack('<HH', 0, tap_header_len)
        pcap_pseudo_header += struct.pack('<HHHH', 3, 3, channel, 0)
        pcap_pseudo_header += struct.pack('<HHf', 1, 4, 0.0) # RSSI placeholder
        
        start_rx_msg = UciMessage(EnumUciMessageType.UCI_MT_COMMAND, 0, EnumUciGid.UWB_SNIFFER_GID.value, 0,
                                    EnumSnifferOid.SNIFFER_START_RX_MODE_OID.value, 0, [])
        start_cmd_bytes = start_rx_msg.to_byte_stream()

        # Instruct proxy to begin fast capture loop directly into the FIFO
        # Keep fifo_file open so the FIFO stays alive while C++ opens it for writing
        proxy_proc = getattr(dongle.ft4222_device, 'proc', None)

        # Register SIGTERM handler so Wireshark stopping the capture kills the proxy cleanly
        def _terminate_proxy(signum, frame):
            log_to_file(f"Received signal {signum}, terminating proxy...")
            try:
                dongle.ft4222_device.close()
            except Exception as close_error:
                log_to_file(f"Error during device shutdown in signal handler: {close_error}")
            try:
                fifo_file.close()
            except Exception:
                pass
            sys.exit(0)

        signal.signal(signal.SIGTERM, _terminate_proxy)
        signal.signal(signal.SIGINT, _terminate_proxy)

        dongle.ft4222_device._send_cmd(f"START_FAST_CAPTURE {fifo} {channel} {int(dongle.ft4222_device.is_ncj29d5)} {pcap_pseudo_header.hex()} {bytes(start_cmd_bytes).hex()}")

        # Keep Python alive while C++ runs. Wireshark closing the pipe or user aborting will terminate C++.
        if proxy_proc:
            proxy_proc.wait()
    except KeyboardInterrupt:
        log_to_file("Capture stopped by user request.")
    finally:
        log_to_file("Closing device connection...")
        try:
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

    args, _ = parser.parse_known_args()

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
