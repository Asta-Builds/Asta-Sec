#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <unistd.h>
#endif

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <pcap.h>

// Ethernet definitions
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV6 0x86DD

// Ensure exact byte packing across compilers
#pragma pack(push, 1)

// Ethernet II Header (14 bytes)
struct EthernetHeader {
    uint8_t  ether_dhost[ETHER_ADDR_LEN]; // Destination MAC
    uint8_t  ether_shost[ETHER_ADDR_LEN]; // Source MAC
    uint16_t ether_type;                 // Protocol type (network byte order)
};

// Simplified IPv4 Header (minimum 20 bytes)
struct IPHeader {
    uint8_t  ip_vhl;      // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t  ip_tos;      // Type of service
    uint16_t ip_len;      // Total packet length
    uint16_t ip_id;       // Identification
    uint16_t ip_off;      // Flags + Fragment offset
    uint8_t  ip_ttl;      // Time to Live
    uint8_t  ip_p;        // Protocol (TCP = 6, UDP = 17, ICMP = 1)
    uint16_t ip_sum;      // Header checksum
    struct in_addr ip_src; // Source IP
    struct in_addr ip_dst; // Destination IP
};

// TCP Header (minimum 20 bytes)
struct TCPHeader {
    uint16_t th_sport;    // Source port
    uint16_t th_dport;    // Destination port
    uint32_t th_seq;      // Sequence number
    uint32_t th_ack;      // Acknowledgment number
    uint8_t  th_offx2;    // Data offset (4 bits) + Reserved (4 bits)
    uint8_t  th_flags;    // Control flags (FIN, SYN, RST, PSH, ACK, URG)
    uint16_t th_win;      // Window size
    uint16_t th_sum;      // Checksum
    uint16_t th_urp;      // Urgent pointer
};

// UDP Header (8 bytes)
struct UDPHeader {
    uint16_t uh_sport;    // Source port
    uint16_t uh_dport;    // Destination port
    uint16_t uh_ulen;     // UDP length
    uint16_t uh_sum;      // Checksum
};

// ICMP Header (4 bytes base)
struct ICMPHeader {
    uint8_t  icmp_type;   // Message type
    uint8_t  icmp_code;   // Sub-code
    uint16_t icmp_sum;    // Checksum
};

// DNS Header (12 bytes)
struct DNSHeader {
    uint16_t id;       // Transaction ID
    uint16_t flags;    // Flags
    uint16_t qdcount;  // Questions count
    uint16_t ancount;  // Answer records count
    uint16_t nscount;  // Authority records count
    uint16_t arcount;  // Additional records count
};

#pragma pack(pop)

// TCP Flag masks
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

// Global handle for clean signal handling (Ctrl+C)
static pcap_t* g_pcap_handle = nullptr;
static uint64_t g_packet_count = 0;

void signalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        std::cout << "\n[*] Stopping packet capture...\n";
        if (g_pcap_handle != nullptr) {
            pcap_breakloop(g_pcap_handle);
        }
    }
}

// Format MAC address as XX:XX:XX:XX:XX:XX
std::string formatMac(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

// Convert TCP flags into readable string [SYN, ACK, etc.]
std::string formatTcpFlags(uint8_t flags) {
    std::string result;
    if (flags & TH_SYN)  result += "SYN ";
    if (flags & TH_ACK)  result += "ACK ";
    if (flags & TH_FIN)  result += "FIN ";
    if (flags & TH_RST)  result += "RST ";
    if (flags & TH_PUSH) result += "PSH ";
    if (flags & TH_URG)  result += "URG ";
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result.empty() ? "None" : result;
}

// Detect and extract HTTP details
struct HttpData {
    bool isHttp = false;
    bool isRequest = false;
    std::string startLine;
    std::string host;
    std::string contentType;
};

HttpData parseHttp(const uint8_t* payload, size_t len) {
    HttpData data;
    if (len < 4) return data;

    std::string raw(reinterpret_cast<const char*>(payload), (std::min)(len, static_cast<size_t>(1024)));
    if (raw.rfind("GET ", 0) == 0 || raw.rfind("POST ", 0) == 0 ||
        raw.rfind("HEAD ", 0) == 0 || raw.rfind("PUT ", 0) == 0 ||
        raw.rfind("DELETE ", 0) == 0 || raw.rfind("OPTIONS ", 0) == 0) {
        data.isHttp = true;
        data.isRequest = true;
    } else if (raw.rfind("HTTP/1.0 ", 0) == 0 || raw.rfind("HTTP/1.1 ", 0) == 0 ||
               raw.rfind("HTTP/2.0 ", 0) == 0) {
        data.isHttp = true;
        data.isRequest = false;
    } else {
        return data;
    }

    std::istringstream stream(raw);
    std::string line;
    if (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        data.startLine = line;
    }

    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("Host: ", 0) == 0) {
            data.host = line.substr(6);
        } else if (line.rfind("Content-Type: ", 0) == 0) {
            data.contentType = line.substr(14);
        }
    }
    return data;
}

// Safely read DNS domain name from packet
bool readDnsName(const uint8_t* buffer, size_t bufferLen, size_t& offset, std::string& outName) {
    size_t cur = offset;
    int jumps = 0;
    bool jumped = false;
    outName.clear();

    while (cur < bufferLen) {
        uint8_t len = buffer[cur];
        if (len == 0) {
            cur++;
            break;
        }
        if ((len & 0xC0) == 0xC0) { // Pointer
            if (cur + 1 >= bufferLen) return false;
            uint16_t ptr = ((len & 0x3F) << 8) | buffer[cur + 1];
            if (!jumped) {
                offset = cur + 2;
                jumped = true;
            }
            if (++jumps > 5 || ptr >= bufferLen) return false;
            cur = ptr;
            continue;
        }
        cur++;
        if (cur + len > bufferLen) return false;
        if (!outName.empty()) outName += ".";
        outName.append(reinterpret_cast<const char*>(buffer + cur), len);
        cur += len;
    }
    if (!jumped) offset = cur;
    return !outName.empty();
}

std::string getDnsTypeStr(uint16_t type) {
    switch (type) {
        case 1:  return "A";
        case 5:  return "CNAME";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 65: return "HTTPS";
        default: return "TYPE" + std::to_string(type);
    }
}

// Packet processing callback executed by libpcap for each captured frame
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    (void)userData;
    g_packet_count++;

    // Ensure frame has at least an Ethernet header
    if (pkthdr->caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* ethHeader = reinterpret_cast<const EthernetHeader*>(packet);
    uint16_t etherType = ntohs(ethHeader->ether_type);

    // Filter for IPv4
    if (etherType != ETHERTYPE_IP) return;

    // Check packet size for IPv4 header
    if (pkthdr->caplen < sizeof(EthernetHeader) + sizeof(IPHeader)) return;

    const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(packet + sizeof(EthernetHeader));
    int ipHeaderLen = (ipHeader->ip_vhl & 0x0F) * 4;
    if (ipHeaderLen < 20) return;

    // Convert IP addresses to human-readable format
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

    // Calculate transport header offset
    const u_char* transportPacket = packet + sizeof(EthernetHeader) + ipHeaderLen;
    size_t remainingBytes = (pkthdr->caplen > sizeof(EthernetHeader) + ipHeaderLen)
                            ? (pkthdr->caplen - sizeof(EthernetHeader) - ipHeaderLen)
                            : 0;

    std::cout << std::dec << "#" << g_packet_count << " ";

    switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            if (remainingBytes >= sizeof(TCPHeader)) {
                const TCPHeader* tcpHeader = reinterpret_cast<const TCPHeader*>(transportPacket);
                uint16_t srcPort = ntohs(tcpHeader->th_sport);
                uint16_t dstPort = ntohs(tcpHeader->th_dport);
                int tcpHeaderLen = ((tcpHeader->th_offx2 >> 4) & 0x0F) * 4;
                int payloadLen = static_cast<int>(remainingBytes) - tcpHeaderLen;
                if (payloadLen < 0) payloadLen = 0;

                const uint8_t* tcpPayload = transportPacket + tcpHeaderLen;
                HttpData http = parseHttp(tcpPayload, payloadLen);

                if (http.isHttp) {
                    std::cout << "[HTTP] "
                              << srcIp << ":" << srcPort << " -> "
                              << dstIp << ":" << dstPort
                              << " | " << http.startLine;
                    if (!http.host.empty()) std::cout << " (Host: " << http.host << ")";
                    std::cout << " | " << pkthdr->len << " B\n";
                } else {
                    std::cout << "[TCP] "
                              << srcIp << ":" << srcPort << " -> "
                              << dstIp << ":" << dstPort
                              << " | Flags: [" << formatTcpFlags(tcpHeader->th_flags) << "]"
                              << " | Payload: " << payloadLen << " B"
                              << " | Total: " << pkthdr->len << " B\n";
                }
            } else {
                std::cout << "[TCP] " << srcIp << " -> " << dstIp
                          << " (Truncated header) | Total: " << pkthdr->len << " B\n";
            }
            break;
        }

        case IPPROTO_UDP: {
            if (remainingBytes >= sizeof(UDPHeader)) {
                const UDPHeader* udpHeader = reinterpret_cast<const UDPHeader*>(transportPacket);
                uint16_t srcPort = ntohs(udpHeader->uh_sport);
                uint16_t dstPort = ntohs(udpHeader->uh_dport);
                int udpDataLen = static_cast<int>(remainingBytes) - sizeof(UDPHeader);
                if (udpDataLen < 0) udpDataLen = 0;

                const uint8_t* udpPayload = transportPacket + sizeof(UDPHeader);

                // Detect DNS Traffic (port 53, 5353, etc.)
                bool isDns = (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353);
                if (isDns && udpDataLen >= static_cast<int>(sizeof(DNSHeader))) {
                    const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(udpPayload);
                    uint16_t flags = ntohs(dns->flags);
                    bool isResponse = (flags >> 15) & 1;
                    size_t offset = sizeof(DNSHeader);
                    std::string qName;

                    if (readDnsName(udpPayload, udpDataLen, offset, qName)) {
                        uint16_t qType = (offset + 2 <= static_cast<size_t>(udpDataLen))
                                         ? ntohs(*reinterpret_cast<const uint16_t*>(udpPayload + offset))
                                         : 0;

                        std::cout << "[DNS] "
                                  << srcIp << ":" << srcPort << " -> "
                                  << dstIp << ":" << dstPort
                                  << " | " << (isResponse ? "Response: " : "Query: ")
                                  << qName << " [" << getDnsTypeStr(qType) << "]"
                                  << " (TxID: 0x" << std::hex << ntohs(dns->id) << std::dec << ")"
                                  << " | Total: " << pkthdr->len << " B\n";
                        break;
                    }
                }

                std::cout << "[UDP] "
                          << srcIp << ":" << srcPort << " -> "
                          << dstIp << ":" << dstPort
                          << " | Length: " << ntohs(udpHeader->uh_ulen) << " B"
                          << " | Total: " << pkthdr->len << " B\n";
            } else {
                std::cout << "[UDP] " << srcIp << " -> " << dstIp
                          << " (Truncated header) | Total: " << pkthdr->len << " B\n";
            }
            break;
        }

        case IPPROTO_ICMP: {
            if (remainingBytes >= sizeof(ICMPHeader)) {
                const ICMPHeader* icmpHeader = reinterpret_cast<const ICMPHeader*>(transportPacket);
                std::string typeDesc = "ICMP";
                if (icmpHeader->icmp_type == 8) typeDesc = "Echo Request (Ping)";
                else if (icmpHeader->icmp_type == 0) typeDesc = "Echo Reply (Ping)";
                else if (icmpHeader->icmp_type == 3) typeDesc = "Dest Unreachable";

                std::cout << "[ICMP] "
                          << srcIp << " -> " << dstIp
                          << " | Type: " << static_cast<int>(icmpHeader->icmp_type)
                          << " (" << typeDesc << ")"
                          << " Code: " << static_cast<int>(icmpHeader->icmp_code)
                          << " | Total: " << pkthdr->len << " B\n";
            } else {
                std::cout << "[ICMP] " << srcIp << " -> " << dstIp
                          << " | Total: " << pkthdr->len << " B\n";
            }
            break;
        }

        default:
            std::cout << "[IP Proto " << static_cast<int>(ipHeader->ip_p) << "] "
                      << srcIp << " -> " << dstIp
                      << " | Total: " << pkthdr->len << " B\n";
            break;
    }
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Initialize Winsock on Windows
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock.\n";
        return 1;
    }
#endif

    // Setup signal handling for clean exit on Ctrl+C
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces = nullptr;

    // 1. Enumerate available network interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1 || interfaces == nullptr) {
        std::cerr << "[!] Error finding network devices: " << errbuf << "\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    std::cout << "========================================\n";
    std::cout << "         C++ Libpcap Sniffer            \n";
    std::cout << "========================================\n";
    std::cout << "[*] Available interfaces:\n";

    std::string selectedDev;
    std::string fallbackDev;

    for (pcap_if_t* d = interfaces; d != nullptr; d = d->next) {
        std::cout << "  - " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        if (d->flags & PCAP_IF_LOOPBACK) {
            std::cout << " [Loopback]";
        }
        std::cout << "\n";

        if (fallbackDev.empty()) {
            fallbackDev = d->name;
        }
        if (selectedDev.empty() && !(d->flags & PCAP_IF_LOOPBACK)) {
            selectedDev = d->name;
        }
    }

    // Fallback to loopback if no external interface is found
    if (selectedDev.empty()) {
        selectedDev = fallbackDev;
    }

    // Interface can be passed as argument: ./sniffer [interface] [filter]
    if (argc >= 2) {
        selectedDev = argv[1];
    }

    std::string filterExp = "ip";
    if (argc >= 3) {
        filterExp = argv[2];
    }

    std::cout << "----------------------------------------\n";
    std::cout << "[*] Selected interface : " << selectedDev << "\n";
    std::cout << "[*] BPF Filter         : " << filterExp << "\n";
    std::cout << "----------------------------------------\n";

    pcap_freealldevs(interfaces);

    // 2. Open interface for live packet capture
    pcap_t* handle = pcap_open_live(selectedDev.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[!] Could not open device " << selectedDev << ": " << errbuf << "\n";
        std::cerr << "[!] Note: Live capture requires elevated privileges (sudo or Administrator).\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    g_pcap_handle = handle;

    // Check link-layer header type (must be Ethernet DLT_EN10MB)
    int linkType = pcap_datalink(handle);
    if (linkType != DLT_EN10MB) {
        std::cerr << "[!] Warning: Interface does not provide Ethernet headers (DLT="
                  << linkType << "). Decoding might differ.\n";
    }

    // 3. Compile and apply Berkeley Packet Filter (BPF)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[!] Could not parse filter '" << filterExp << "': "
                  << pcap_geterr(handle) << "\n";
        pcap_close(handle);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[!] Could not set filter: " << pcap_geterr(handle) << "\n";
        pcap_freecode(&fp);
        pcap_close(handle);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    std::cout << "[*] Sniffer running. Press Ctrl+C to stop.\n\n";

    // 4. Start the packet capture loop (0 = capture until interrupted or error)
    pcap_loop(handle, 0, packetHandler, nullptr);

    // 5. Print statistics and clean up
    struct pcap_stat stats;
    if (pcap_stats(handle, &stats) >= 0) {
        std::cout << "\n---------------- Capture Summary ----------------\n";
        std::cout << "Packets received by filter : " << stats.ps_recv << "\n";
        std::cout << "Packets dropped by kernel  : " << stats.ps_drop << "\n";
        std::cout << "Packets processed in loop  : " << g_packet_count << "\n";
        std::cout << "-------------------------------------------------\n";
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    g_pcap_handle = nullptr;

#ifdef _WIN32
    WSACleanup();
#endif

    std::cout << "[*] Sniffer exited cleanly.\n";
    return 0;
}
