#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <thread>
#include <chrono>
#include <poll.h>

typedef void* FT_HANDLE;
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t UCHAR;
typedef int FT_STATUS;

#define FT_OK 0
#define FT_OPEN_BY_LOCATION 4

typedef FT_STATUS (*pFT_OpenEx)(void* pArg1, DWORD Flags, FT_HANDLE* pHandle);
typedef FT_STATUS (*pFT4222_SetClock)(FT_HANDLE handle, UCHAR clk);
typedef FT_STATUS (*pFT4222_SPIMaster_Init)(FT_HANDLE handle, int ioLine, int clock, int cpol, int cpha, uint8_t ssoMap);
typedef FT_STATUS (*pFT4222_SPI_SetDrivingStrength)(FT_HANDLE handle, int clkStrength, int ioStrength, int ssoStrength);
typedef FT_STATUS (*pFT_SetTimeouts)(FT_HANDLE handle, DWORD ReadTimeout, DWORD WriteTimeout);
typedef FT_STATUS (*pFT4222_GPIO_Init)(FT_HANDLE handle, int gpioDir[4]);
typedef FT_STATUS (*pFT4222_SetSuspendOut)(FT_HANDLE handle, bool enable);
typedef FT_STATUS (*pFT4222_SetWakeUpInterrupt)(FT_HANDLE handle, bool enable);
typedef FT_STATUS (*pFT4222_GPIO_Write)(FT_HANDLE handle, uint32_t portNum, bool bValue);
typedef FT_STATUS (*pFT4222_GPIO_Read)(FT_HANDLE handle, uint32_t portNum, bool* bValue);
typedef FT_STATUS (*pFT4222_SPI_Reset)(FT_HANDLE handle);
typedef FT_STATUS (*pFT4222_SPIMaster_SingleReadWrite)(FT_HANDLE handle, uint8_t* readBuffer, uint8_t* writeBuffer, uint16_t bufferSize, uint16_t* sizeTransferred, bool isEndTransaction);
typedef FT_STATUS (*pFT_Close)(FT_HANDLE handle);

pFT_OpenEx FT_OpenEx = nullptr;
pFT4222_SetClock FT4222_SetClock = nullptr;
pFT4222_SPIMaster_Init FT4222_SPIMaster_Init = nullptr;
pFT4222_SPI_SetDrivingStrength FT4222_SPI_SetDrivingStrength = nullptr;
pFT_SetTimeouts FT_SetTimeouts = nullptr;
pFT4222_GPIO_Init FT4222_GPIO_Init = nullptr;
pFT4222_SetSuspendOut FT4222_SetSuspendOut = nullptr;
pFT4222_SetWakeUpInterrupt FT4222_SetWakeUpInterrupt = nullptr;
pFT4222_GPIO_Write FT4222_GPIO_Write = nullptr;
pFT4222_GPIO_Read FT4222_GPIO_Read = nullptr;
pFT4222_SPI_Reset FT4222_SPI_Reset = nullptr;
pFT4222_SPIMaster_SingleReadWrite FT4222_SPIMaster_SingleReadWrite = nullptr;
pFT_Close FT_Close = nullptr;

bool load_ftdi_library(const std::string& path) {
    // Load libftd2xx.dylib first because libft4222 depends on it
    std::string d2xx_path = path.substr(0, path.find_last_of('/')) + "/libftd2xx.dylib";
    void* handle_d2xx = dlopen(d2xx_path.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (!handle_d2xx) {
        std::cerr << "ERR Failed to load libftd2xx: " << dlerror() << std::endl;
        return false;
    }

    void* handle_4222 = dlopen(path.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (!handle_4222) {
        std::cerr << "ERR Failed to load libft4222: " << dlerror() << std::endl;
        return false;
    }

    FT_OpenEx = (pFT_OpenEx)dlsym(handle_d2xx, "FT_OpenEx");
    FT_Close = (pFT_Close)dlsym(handle_d2xx, "FT_Close");
    FT_SetTimeouts = (pFT_SetTimeouts)dlsym(handle_d2xx, "FT_SetTimeouts");

    FT4222_SetClock = (pFT4222_SetClock)dlsym(handle_4222, "FT4222_GetClock"); // Wait! FT4222_SetClock symbol is actually FT4222_SetClock
    // let's dynamically load FT4222_SetClock
    FT4222_SetClock = (pFT4222_SetClock)dlsym(handle_4222, "FT4222_SetClock");
    FT4222_SPIMaster_Init = (pFT4222_SPIMaster_Init)dlsym(handle_4222, "FT4222_SPIMaster_Init");
    FT4222_SPI_SetDrivingStrength = (pFT4222_SPI_SetDrivingStrength)dlsym(handle_4222, "FT4222_SPI_SetDrivingStrength");
    FT4222_GPIO_Init = (pFT4222_GPIO_Init)dlsym(handle_4222, "FT4222_GPIO_Init");
    FT4222_SetSuspendOut = (pFT4222_SetSuspendOut)dlsym(handle_4222, "FT4222_SetSuspendOut");
    FT4222_SetWakeUpInterrupt = (pFT4222_SetWakeUpInterrupt)dlsym(handle_4222, "FT4222_SetWakeUpInterrupt");
    FT4222_GPIO_Write = (pFT4222_GPIO_Write)dlsym(handle_4222, "FT4222_GPIO_Write");
    FT4222_GPIO_Read = (pFT4222_GPIO_Read)dlsym(handle_4222, "FT4222_GPIO_Read");
    FT4222_SPI_Reset = (pFT4222_SPI_Reset)dlsym(handle_4222, "FT4222_SPI_Reset");
    FT4222_SPIMaster_SingleReadWrite = (pFT4222_SPIMaster_SingleReadWrite)dlsym(handle_4222, "FT4222_SPIMaster_SingleReadWrite");

    if (!FT_OpenEx || !FT4222_SPIMaster_SingleReadWrite || !FT4222_GPIO_Read) {
        std::cerr << "ERR Failed to bind FTDI symbols!" << std::endl;
        return false;
    }
    return true;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

FT_HANDLE spi_handle = nullptr;
FT_HANDLE gpio_handle = nullptr;

void cpp_capture_loop(const std::string& fifo_path, uint32_t channel, const std::vector<uint8_t>& tap_hdr, const std::vector<uint8_t>& start_rx_cmd, bool is_ncj29d5) {
    // fifo_path may be a numeric fd (inherited from Python) or a filesystem path
    int fifo_fd = -1;
    bool is_fd_number = !fifo_path.empty() && std::all_of(fifo_path.begin(), fifo_path.end(), ::isdigit);
    if (is_fd_number) {
        fifo_fd = std::stoi(fifo_path);
        fprintf(stderr, "INFO Using inherited FIFO fd: %d\n", fifo_fd); fflush(stderr);
    } else {
        fprintf(stderr, "INFO Opening FIFO path: %s\n", fifo_path.c_str()); fflush(stderr);
        fifo_fd = open(fifo_path.c_str(), O_WRONLY);
        if (fifo_fd < 0) {
            fprintf(stderr, "ERR Failed to open FIFO path\n"); fflush(stderr);
            return;
        }
    }
    fprintf(stderr, "INFO C++ capture loop started. FD: %d\n", fifo_fd); fflush(stderr);

    bool rx_mode_started = false;
    std::vector<uint8_t> tap = tap_hdr;
    std::vector<uint8_t> pcap_pkt_hdr(16, 0);
    while(true) {
        bool int_n_current = true;
        FT4222_GPIO_Read(gpio_handle, 3, &int_n_current);

        if (!rx_mode_started && int_n_current) {
            uint16_t transferred = 0;
            FT4222_GPIO_Write(gpio_handle, 2, false); // CS_N LOW
            // Wait for RDY_N to go low (chip signals ready after CS_N asserted)
            bool rdy = true;
            for (int i=0; i<10000; i++) {
                FT4222_GPIO_Read(gpio_handle, 1, &rdy);
                if (!rdy) break;
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
            if (rdy) {
                // RDY_N never went low — chip not ready. Release CS_N and skip this cycle.
                fprintf(stderr, "WARN RDY_N timeout for START_RX_MODE retry, skipping.\n"); fflush(stderr);
                FT4222_GPIO_Write(gpio_handle, 2, true);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            std::vector<uint8_t> dummy_rx(start_rx_cmd.size(), 0);
            FT_STATUS status = FT4222_SPIMaster_SingleReadWrite(spi_handle, dummy_rx.data(), (uint8_t*)start_rx_cmd.data(), start_rx_cmd.size(), &transferred, true);
            FT4222_GPIO_Write(gpio_handle, 2, true);
            fprintf(stderr, "INFO Sent START_RX_MODE! RDY_N was %s, Status: %d, Transferred: %d\n", rdy ? "HIGH (timeout)" : "LOW (ok)", status, transferred); fflush(stderr);
            rx_mode_started = true; // mark as sent, chip will assert INT_N when ready
            std::this_thread::sleep_for(std::chrono::milliseconds(5)); // small gap before waiting for INT_N
        }

        // 2. Wait for INT_N (P3) to go low
        bool int_n = true;
        auto wait_start = std::chrono::steady_clock::now();
        while (int_n) {
            // Check if FIFO was closed by Wireshark OR if Python parent died (stdin EOF)
            struct pollfd pfds[2];
            pfds[0].fd = fifo_fd;
            pfds[0].events = POLLERR | POLLHUP;
            pfds[1].fd = STDIN_FILENO;
            pfds[1].events = POLLIN | POLLHUP;
            if (poll(pfds, 2, 0) > 0) {
                if (pfds[0].revents & (POLLERR | POLLHUP)) {
                    fprintf(stderr, "INFO FIFO closed. Terminating.\n"); fflush(stderr);
                    return;
                }
                if (pfds[1].revents & (POLLIN | POLLHUP)) {
                    // stdin readable = EOF or command; any stdin activity means we should terminate
                    char buf[16];
                    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
                    if (n <= 0) {
                        fprintf(stderr, "INFO stdin EOF. Python parent died. Terminating.\n"); fflush(stderr);
                    } else {
                        fprintf(stderr, "INFO Received stdin command during capture. Terminating.\n"); fflush(stderr);
                    }
                    return;
                }
            }

            FT4222_GPIO_Read(gpio_handle, 3, &int_n);
            if (!int_n) break;
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - wait_start).count() > 30000) {
                // If it takes more than 30 seconds without any INT_N,
                // the hardware might have dropped the RX command or hung.
                // We should break and force restart RX mode!
                fprintf(stderr, "WARN INT_N timeout! Resending START_RX_MODE.\n"); fflush(stderr);
                rx_mode_started = false;
                break;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }

        if (int_n) {
            // Timed out! The hardware didn't respond. Restart loop to retry START_RX_MODE.
            continue;
        }

        // For NCJ29D5: response reads do NOT use RDY_N - just assert CS_N and read immediately
        FT4222_GPIO_Write(gpio_handle, 2, false); // CS_N LOW
        int hdr_len = is_ncj29d5 ? 5 : 4;
        std::vector<uint8_t> header_tx(hdr_len, 0);
        std::vector<uint8_t> header_rx(hdr_len, 0);
        uint16_t transferred = 0;
        FT4222_SPIMaster_SingleReadWrite(spi_handle, header_rx.data(), header_tx.data(), hdr_len, &transferred, false);

        // Log all raw header bytes
        fprintf(stderr, "INFO Raw header (%d bytes):", hdr_len);
        for (int i = 0; i < hdr_len; i++) fprintf(stderr, " %02X", header_rx[i]);
        fprintf(stderr, "\n"); fflush(stderr);

        uint16_t payload_len = is_ncj29d5 ? (header_rx[4] | (header_rx[3] << 8)) : (header_rx[3] | (header_rx[2] << 8));
        if (payload_len > 512) {
            fprintf(stderr, "WARN Suspicious payload_len=%d, skipping frame.\n", payload_len); fflush(stderr);
            // Wait for INT_N to go high before releasing CS_N
            bool int_n_hi = false;
            for (int i = 0; i < 10000 && !int_n_hi; i++) {
                FT4222_GPIO_Read(gpio_handle, 3, &int_n_hi);
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
            FT4222_GPIO_Write(gpio_handle, 2, true); // CS_N HIGH
            rx_mode_started = false;
            continue;
        }
        std::vector<uint8_t> payload_tx(payload_len + 2, 0);
        std::vector<uint8_t> payload_rx(payload_len + 2, 0);
        FT4222_SPIMaster_SingleReadWrite(spi_handle, payload_rx.data(), payload_tx.data(), payload_len + 2, &transferred, false);

        // Wait for INT_N to go HIGH before releasing CS_N (matching Python driver)
        bool int_n_hi = false;
        for (int i = 0; i < 10000 && !int_n_hi; i++) {
            FT4222_GPIO_Read(gpio_handle, 3, &int_n_hi);
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        FT4222_GPIO_Write(gpio_handle, 2, true); // CS_N HIGH - AFTER INT_N goes high

        std::vector<uint8_t> uci_frame;
        if (is_ncj29d5) {
            for (int i = 1; i < 5; i++) uci_frame.push_back(header_rx[i]);
        } else {
            for (int i = 0; i < 4; i++) uci_frame.push_back(header_rx[i]);
        }
        uci_frame.insert(uci_frame.end(), payload_rx.begin(), payload_rx.end() - 2);

        if (uci_frame.size() >= 4) {
            fprintf(stderr, "INFO UCI Header: %02X %02X %02X %02X\n", uci_frame[0], uci_frame[1], uci_frame[2], uci_frame[3]);
            fflush(stderr);
        }

        if (uci_frame.size() >= 4 && uci_frame[0] == 0x4E && uci_frame[1] == 0x1B) {
            const std::vector<uint8_t>& pl = uci_frame;
            if (pl.size() >= 5) {
                uint8_t rx_status_byte = pl[4];
                if (rx_status_byte == 0x00 && pl.size() >= 4 + 33) {
                    uint8_t uwb_payload_len = pl[4 + 32];
                    int32_t max_rssi_raw = (int32_t)(pl[4+16] | (pl[4+17]<<8) | (pl[4+18]<<16) | (pl[4+19]<<24));
                    float max_rssi = (float)max_rssi_raw * 10.0f * 0.30103f / (float)(1 << 25);

                    if (uwb_payload_len > 0 && pl.size() >= (size_t)(4 + 33 + uwb_payload_len)) {
                        const uint8_t* frame_data = &pl[4 + 33];
                        struct timeval tv;
                        gettimeofday(&tv, NULL);
                        uint32_t pcap_length = uwb_payload_len + tap_hdr.size();
                        uint32_t pcap_pkt_hdr_arr[4] = {(uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec, pcap_length, pcap_length};
                        std::vector<uint8_t> tap_out = tap_hdr;
                        memcpy(&tap_out[16], &max_rssi, 4);
                        std::vector<uint8_t> pkt_record;
                        pkt_record.insert(pkt_record.end(), (uint8_t*)pcap_pkt_hdr_arr, (uint8_t*)pcap_pkt_hdr_arr + 16);
                        pkt_record.insert(pkt_record.end(), tap_out.begin(), tap_out.end());
                        pkt_record.insert(pkt_record.end(), frame_data, frame_data + uwb_payload_len);
                        write(fifo_fd, pkt_record.data(), pkt_record.size());
                    }
                }
            }
            rx_mode_started = false;
            continue;
        }

    } // end while(true)
} // end fast_capture_loop

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: cpp_usb_capture <libft4222.dylib path>" << std::endl;
        return 1;
    }

    if (!load_ftdi_library(argv[1])) {
        return 1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        std::string req(line);
        if (!req.empty() && req.back() == '\n') req.pop_back();
        if (req.empty()) continue;

        fprintf(stderr, "PROXY RECV: %s\n", req.c_str()); fflush(stderr);

        std::stringstream ss(req);
        std::string cmd;
        ss >> cmd;

        if (cmd == "OPEN") {
            int loc; ss >> loc;
            FT_STATUS status = FT_OpenEx((void*)(uintptr_t)loc, FT_OPEN_BY_LOCATION, &spi_handle);
            if (status != FT_OK) std::cout << "ERR " << status << std::endl;
            else std::cout << "OK" << std::endl;
        }
        else if (cmd == "OPEN_GPIO") {
            int loc; ss >> loc;
            FT_STATUS status = FT_OpenEx((void*)(uintptr_t)loc, FT_OPEN_BY_LOCATION, &gpio_handle);
            if (status != FT_OK) std::cout << "ERR " << status << std::endl;
            else std::cout << "OK" << std::endl;
        }
        else if (cmd == "SET_CLOCK") {
            int clk; ss >> clk;
            FT_STATUS status = FT4222_SetClock(spi_handle, clk);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "SPI_INIT") {
            int mode, clk, cpol, cpha, sso;
            ss >> mode >> clk >> cpol >> cpha >> sso;
            FT_STATUS status = FT4222_SPIMaster_Init(spi_handle, mode, clk, cpol, cpha, sso);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "SPI_DRIVING") {
            int clk_str, io_str, sso_str;
            ss >> clk_str >> io_str >> sso_str;
            FT_STATUS status = FT4222_SPI_SetDrivingStrength(spi_handle, clk_str, io_str, sso_str);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "SET_TIMEOUTS") {
            int rx_to, tx_to;
            ss >> rx_to >> tx_to;
            FT_STATUS status = FT_SetTimeouts(spi_handle, rx_to, tx_to);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "GPIO_INIT") {
            int d0, d1, d2, d3;
            ss >> d0 >> d1 >> d2 >> d3;
            int dirs[4] = {d0, d1, d2, d3};
            FT_STATUS status = FT4222_GPIO_Init(gpio_handle, dirs);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "SET_SUSPEND_OUT") {
            int val; ss >> val;
            FT_STATUS status = FT4222_SetSuspendOut(gpio_handle, val);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "SET_WAKE_UP_INTERRUPT") {
            int val; ss >> val;
            FT_STATUS status = FT4222_SetWakeUpInterrupt(gpio_handle, val);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "SPI_RESET") {
            FT_STATUS status = FT4222_SPI_Reset(spi_handle);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "GPIO_WRITE") {
            int port, val;
            ss >> port >> val;
            FT_STATUS status = FT4222_GPIO_Write(gpio_handle, port, val);
            std::cout << (status == FT_OK ? "OK" : "ERR") << std::endl;
        }
        else if (cmd == "GPIO_READ") {
            int port; ss >> port;
            bool val = false;
            FT_STATUS status = FT4222_GPIO_Read(gpio_handle, port, &val);
            if (status == FT_OK) std::cout << "VAL " << (int)val << std::endl;
            else std::cout << "ERR" << std::endl;
        }
        else if (cmd == "SPI_XFER") {
            int is_end;
            std::string hex;
            ss >> is_end >> hex;
            std::vector<uint8_t> tx = hex_to_bytes(hex);
            std::vector<uint8_t> rx(tx.size(), 0);
            uint16_t transferred = 0;
            FT_STATUS status = FT4222_SPIMaster_SingleReadWrite(spi_handle, rx.data(), tx.data(), tx.size(), &transferred, is_end);
            if (status == FT_OK) {
                std::cout << "RX " << bytes_to_hex(rx.data(), transferred) << std::endl;
            } else {
                std::cout << "ERR " << status << std::endl;
            }
        }
        else if (cmd == "START_CPP_CAPTURE") {
            std::string fifo;
            int channel;
            int is_ncj29d5;
            std::string tap_hex;
            std::string start_cmd_hex;
            ss >> fifo >> channel >> is_ncj29d5 >> tap_hex >> start_cmd_hex;
            
            std::vector<uint8_t> tap = hex_to_bytes(tap_hex);
            std::vector<uint8_t> rx_cmd = hex_to_bytes(start_cmd_hex);
            
            std::cout << "OK" << std::endl; // Confirm transition
            
            cpp_capture_loop(fifo, channel, tap, rx_cmd, is_ncj29d5);
            break; // Exit after loop completes or fails
        }
        else if (cmd == "CLOSE") {
            if (spi_handle) FT_Close(spi_handle);
            if (gpio_handle) FT_Close(gpio_handle);
            std::cout << "OK" << std::endl;
            break;
        }
        else {
            std::cout << "UNKNOWN" << std::endl;
        }
    }

    if (spi_handle) {
        FT_Close(spi_handle);
    }
    if (gpio_handle) {
        FT_Close(gpio_handle);
    }
    return 0;
}
