#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <pcap.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef SOCKET socket_t;
  #define IS_INVALID_SOCKET(s) ((s) == INVALID_SOCKET)
  #define CLOSE_SOCKET(s) closesocket(s)
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  typedef int socket_t;
  #define INVALID_SOCKET (-1)
  #define IS_INVALID_SOCKET(s) ((s) < 0)
  #define CLOSE_SOCKET(s) close(s)
#endif

// ==========================================
// Protocol Constants & Enums
// ==========================================
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV6 0x86DD

#define ARPHRD_ETHER   1
#define ARPOP_REQUEST  1
#define ARPOP_REPLY    2

#pragma pack(push, 1)

// Ethernet II Header (14 bytes)
struct EthernetHeader {
    uint8_t  ether_dhost[ETHER_ADDR_LEN]; // Destination MAC
    uint8_t  ether_shost[ETHER_ADDR_LEN]; // Source MAC
    uint16_t ether_type;                 // Protocol type
};

// IPv4 Header (minimum 20 bytes)
struct IPHeader {
    uint8_t  ip_vhl;      // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t  ip_tos;      // Type of service
    uint16_t ip_len;      // Total packet length
    uint16_t ip_id;       // Identification
    uint16_t ip_off;      // Flags (3 bits) + Fragment offset (13 bits)
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
    uint8_t  th_flags;    // Flags
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

// ICMP Header (4 bytes minimum)
struct ICMPHeader {
    uint8_t  icmp_type;   // Message type
    uint8_t  icmp_code;   // Sub-code
    uint16_t icmp_sum;    // Checksum
};

// ARP Header (28 bytes for IPv4 over Ethernet)
struct ARPHeader {
    uint16_t ar_hrd;                    // Hardware format
    uint16_t ar_pro;                    // Protocol format
    uint8_t  ar_hln;                    // Hardware address length (6)
    uint8_t  ar_pln;                    // Protocol address length (4)
    uint16_t ar_op;                     // Opcode (1=req, 2=reply)
    uint8_t  ar_sha[ETHER_ADDR_LEN];    // Sender hardware address
    struct in_addr ar_spa;              // Sender protocol address
    uint8_t  ar_tha[ETHER_ADDR_LEN];    // Target hardware address
    struct in_addr ar_tpa;              // Target protocol address
};

// DNS Header (12 bytes)
struct DNSHeader {
    uint16_t id;       // Identification number
    uint16_t flags;    // DNS flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qdcount;  // Question count
    uint16_t ancount;  // Answer record count
    uint16_t nscount;  // Authority record count
    uint16_t arcount;  // Additional record count
};

#pragma pack(pop)

// TCP Flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

// ==========================================
// Terminal Color Support
// ==========================================
struct Colors {
    bool enabled = true;
    std::string reset   = "\033[0m";
    std::string bold    = "\033[1m";
    std::string dim     = "\033[2m";
    std::string red     = "\033[31m";
    std::string green   = "\033[32m";
    std::string yellow  = "\033[33m";
    std::string blue    = "\033[34m";
    std::string magenta = "\033[35m";
    std::string cyan    = "\033[36m";
    std::string white   = "\033[37m";

    std::string b_red   = "\033[1;31m";
    std::string b_green = "\033[1;32m";
    std::string b_yellow= "\033[1;33m";
    std::string b_cyan  = "\033[1;36m";
    std::string b_magenta="\033[1;35m";
    std::string b_white = "\033[1;37m";

    void disable() {
        enabled = false;
        reset = bold = dim = red = green = yellow = blue = magenta = cyan = white = "";
        b_red = b_green = b_yellow = b_cyan = b_magenta = b_white = "";
    }
} clr;

// ==========================================
// CLI Options & State
// ==========================================
struct Config {
    std::string interfaceName;
    std::string filter = "ip or arp";
    std::string pcapOutputFile;
    uint64_t maxPackets = 0; // 0 = continuous
    bool verbose = false;
    bool showHex = false;
    bool listInterfacesOnly = false;
    std::string auditTarget;
    std::string scanTarget;
    std::string dnsQueryTarget;
    std::string subdomainsTarget;
} cfg;

struct Stats {
    uint64_t totalPackets = 0;
    uint64_t tcpPackets = 0;
    uint64_t udpPackets = 0;
    uint64_t icmpPackets = 0;
    uint64_t arpPackets = 0;
    uint64_t httpPackets = 0;
    uint64_t dnsPackets = 0;
    uint64_t otherPackets = 0;
    uint64_t totalBytes = 0;
    std::chrono::steady_clock::time_point startTime;
} stats;

static pcap_t* g_pcap_handle = nullptr;
static pcap_dumper_t* g_pcap_dumper = nullptr;

// ==========================================
// Banner & UI Helpers
// ==========================================
void printBanner() {
    std::cout << clr.b_cyan
              << "  █████╗ ███████╗████████╗ █████╗        ███████╗███████╗ ██████╗ \n"
              << " ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗       ██╔════╝██╔════╝██╔════╝ \n"
              << " ███████║███████╗   ██║   ███████║ █████╗███████╗█████╗  ██║      \n"
              << " ██╔══██║╚════██║   ██║   ██╔══██║ ╚════╝╚════██║██╔══╝  ██║      \n"
              << " ██║  ██║███████║   ██║   ██║  ██║       ███████║███████╗╚██████╗ \n"
              << " ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝       ╚══════╝╚══════╝ ╚═════╝ \n"
              << clr.reset;
    std::cout << clr.b_yellow << "      [ ASTA-SEC // ADVANCED SECURITY & NETWORK SUITE v2.0 ]\n" << clr.reset;
    std::cout << clr.dim      << "   Sniffer | OWASP Web Auditor | Subdomain Recon | Nmap Scanner\n" << clr.reset;
    std::cout << clr.dim      << " ----------------------------------------------------------------\n" << clr.reset;
}

void printUsage(const char* progName) {
    std::cout << clr.bold << "Usage:" << clr.reset << "\n"
              << "  " << progName << " [OPTIONS]\n"
              << "  " << progName << "               (Launches Interactive Menu mode)\n\n"
              << clr.bold << "Modes & Actions:" << clr.reset << "\n"
              << "  " << clr.b_white << "-m, --menu"                 << clr.reset
              << "              Launch Antigravity-style Interactive Menu\n"
              << "  " << clr.b_white << "--audit <url/host>"        << clr.reset
              << "      Audit website security headers (OWASP/Nessus style)\n"
              << "  " << clr.b_white << "--subdomains <domain>"      << clr.reset
              << " Search subdomains & attack surface (DNS + Web)\n"
              << "  " << clr.b_white << "--scan <host>"             << clr.reset
              << "          Scan host ports & services (Nmap style)\n"
              << "  " << clr.b_white << "--dns <domain>"            << clr.reset
              << "          Query and decode domain DNS records\n"
              << "  " << clr.b_white << "-l, --list"                << clr.reset
              << "                 List all network interfaces and exit\n\n"
              << clr.bold << "Sniffer Options:" << clr.reset << "\n"
              << "  " << clr.b_white << "-i, --interface <id|name>" << clr.reset
              << "  Interface name or numeric index from --list\n"
              << "  " << clr.b_white << "-f, --filter <bpf>"        << clr.reset
              << "         BPF capture filter (default: \"ip or arp\")\n"
              << "  " << clr.b_white << "-c, --count <n>"           << clr.reset
              << "            Exit capture after N packets (0 = infinite)\n"
              << "  " << clr.b_white << "-w, --write <file>"        << clr.reset
              << "         Save captured packets to a PCAP dump file\n"
              << "  " << clr.b_white << "-v, --verbose"             << clr.reset
              << "              Show detailed packet headers & fields\n"
              << "  " << clr.b_white << "-x, --hex"                 << clr.reset
              << "                  Display formatted Hex & ASCII payload dump\n"
              << "  " << clr.b_white << "--no-color"                << clr.reset
              << "               Disable ANSI color output\n"
              << "  " << clr.b_white << "-h, --help"                << clr.reset
              << "                 Display this help menu\n\n"
              << clr.bold << "Quick Examples:" << clr.reset << "\n"
              << "  " << progName << " --audit google.com\n"
              << "  " << progName << " --subdomains example.com\n"
              << "  " << progName << " --scan scanme.nmap.org\n"
              << "  " << progName << " -i 1 -f \"tcp port 80 or udp port 53\" -x\n\n";
}

// Convert MAC address to string
std::string formatMac(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

// Port to service name helper
std::string getServiceName(uint16_t port) {
    switch (port) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67:
        case 68:   return "DHCP";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 123:  return "NTP";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 993:  return "IMAPS";
        case 995:  return "POP3S";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5353: return "mDNS";
        case 5355: return "LLMNR";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        default:   return "";
    }
}

// Format TCP Flags
std::string formatTcpFlags(uint8_t flags) {
    std::string s;
    if (flags & TH_SYN)  s += "SYN ";
    if (flags & TH_ACK)  s += "ACK ";
    if (flags & TH_FIN)  s += "FIN ";
    if (flags & TH_RST)  s += "RST ";
    if (flags & TH_PUSH) s += "PSH ";
    if (flags & TH_URG)  s += "URG ";
    if (flags & TH_ECE)  s += "ECE ";
    if (flags & TH_CWR)  s += "CWR ";
    if (!s.empty() && s.back() == ' ') s.pop_back();
    return s.empty() ? "None" : s;
}

// Formatted Hex + ASCII dump
void printHexAscii(const uint8_t* data, size_t length) {
    if (length == 0) return;
    std::cout << clr.dim;
    for (size_t i = 0; i < length; i += 16) {
        std::cout << "    " << std::hex << std::setw(4) << std::setfill('0') << i << "  ";

        for (size_t j = 0; j < 16; ++j) {
            if (i + j < length) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(data[i + j]) << " ";
            } else {
                std::cout << "   ";
            }
            if (j == 7) std::cout << " ";
        }

        std::cout << " |";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < length) {
                char c = static_cast<char>(data[i + j]);
                std::cout << (c >= 32 && c <= 126 ? c : '.');
            } else {
                std::cout << " ";
            }
        }
        std::cout << "|\n";
    }
    std::cout << clr.reset << std::dec;
}

// ==========================================
// HTTP Protocol Inspection
// ==========================================
struct HttpInfo {
    bool isHttp = false;
    bool isRequest = false;
    std::string startLine;
    std::string host;
    std::string userAgent;
    std::string contentType;
    std::string contentLength;
    std::string server;
};

HttpInfo parseHttp(const uint8_t* payload, size_t len) {
    HttpInfo info;
    if (len < 4) return info;

    std::string raw(reinterpret_cast<const char*>(payload), std::min(len, size_t(1024)));

    if (raw.rfind("GET ", 0) == 0 || raw.rfind("POST ", 0) == 0 ||
        raw.rfind("HEAD ", 0) == 0 || raw.rfind("PUT ", 0) == 0 ||
        raw.rfind("DELETE ", 0) == 0 || raw.rfind("OPTIONS ", 0) == 0 ||
        raw.rfind("PATCH ", 0) == 0) {
        info.isHttp = true;
        info.isRequest = true;
    } else if (raw.rfind("HTTP/1.0 ", 0) == 0 || raw.rfind("HTTP/1.1 ", 0) == 0 ||
               raw.rfind("HTTP/2.0 ", 0) == 0) {
        info.isHttp = true;
        info.isRequest = false;
    } else {
        return info;
    }

    std::istringstream stream(raw);
    std::string line;
    if (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        info.startLine = line;
    }

    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("Host: ", 0) == 0 || line.rfind("host: ", 0) == 0) {
            info.host = line.substr(6);
        } else if (line.rfind("User-Agent: ", 0) == 0 || line.rfind("user-agent: ", 0) == 0) {
            info.userAgent = line.substr(12);
        } else if (line.rfind("Content-Type: ", 0) == 0 || line.rfind("content-type: ", 0) == 0) {
            info.contentType = line.substr(14);
        } else if (line.rfind("Content-Length: ", 0) == 0 || line.rfind("content-length: ", 0) == 0) {
            info.contentLength = line.substr(16);
        } else if (line.rfind("Server: ", 0) == 0 || line.rfind("server: ", 0) == 0) {
            info.server = line.substr(8);
        }
    }

    return info;
}

// ==========================================
// DNS Protocol Inspection
// ==========================================
std::string dnsTypeToString(uint16_t type) {
    switch (type) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 65:  return "HTTPS";
        case 255: return "ANY";
        default:  return "TYPE" + std::to_string(type);
    }
}

std::string dnsRcodeToString(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NoError";
        case 1: return "FormatError";
        case 2: return "ServerFailure";
        case 3: return "NXDomain";
        case 4: return "NotImplemented";
        case 5: return "Refused";
        default: return "RCODE" + std::to_string(rcode);
    }
}

bool readDnsName(const uint8_t* buffer, size_t bufferLen, size_t& offset, std::string& outName) {
    size_t cur = offset;
    int jumps = 0;
    const int maxJumps = 6;
    bool jumped = false;
    outName.clear();

    while (cur < bufferLen) {
        uint8_t len = buffer[cur];
        if (len == 0) {
            cur++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= bufferLen) return false;
            uint16_t ptr = ((len & 0x3F) << 8) | buffer[cur + 1];
            if (!jumped) {
                offset = cur + 2;
                jumped = true;
            }
            if (++jumps > maxJumps || ptr >= bufferLen) return false;
            cur = ptr;
            continue;
        }

        cur++;
        if (cur + len > bufferLen) return false;
        if (!outName.empty()) outName += ".";
        outName.append(reinterpret_cast<const char*>(buffer + cur), len);
        cur += len;
    }

    if (!jumped) {
        offset = cur;
    }
    return !outName.empty();
}

struct DnsAnswer {
    std::string name;
    std::string type;
    std::string data;
    uint32_t ttl = 0;
};

struct DnsInfo {
    bool isDns = false;
    uint16_t txId = 0;
    bool isResponse = false;
    std::string rcode;
    uint16_t qCount = 0;
    uint16_t ansCount = 0;
    std::string queryName;
    std::string queryType;
    std::vector<DnsAnswer> answers;
};

DnsInfo parseDns(const uint8_t* payload, size_t len) {
    DnsInfo info;
    if (len < sizeof(DNSHeader)) return info;

    const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(payload);
    info.txId = ntohs(dns->id);
    uint16_t flags = ntohs(dns->flags);
    info.isResponse = (flags >> 15) & 1;
    info.rcode = dnsRcodeToString(flags & 0x0F);
    info.qCount = ntohs(dns->qdcount);
    info.ansCount = ntohs(dns->ancount);

    if (info.qCount > 20 || info.ansCount > 50) return info;

    size_t offset = sizeof(DNSHeader);

    if (info.qCount > 0) {
        if (readDnsName(payload, len, offset, info.queryName)) {
            if (offset + 4 <= len) {
                uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
                info.queryType = dnsTypeToString(qtype);
                offset += 4;
                info.isDns = true;
            }
        }
    }

    if (info.isResponse && info.ansCount > 0 && info.isDns) {
        for (uint16_t i = 0; i < info.ansCount && offset < len && i < 5; ++i) {
            std::string ansName;
            if (!readDnsName(payload, len, offset, ansName)) break;

            if (offset + 10 > len) break;
            uint16_t atype = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
            uint32_t attl = ntohl(*reinterpret_cast<const uint32_t*>(payload + offset + 4));
            uint16_t ardlen = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset + 8));
            offset += 10;

            if (offset + ardlen > len) break;

            DnsAnswer ans;
            ans.name = ansName;
            ans.type = dnsTypeToString(atype);
            ans.ttl = attl;

            if (atype == 1 && ardlen == 4) {
                char ipBuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, payload + offset, ipBuf, INET_ADDRSTRLEN);
                ans.data = ipBuf;
                info.answers.push_back(ans);
            } else if (atype == 28 && ardlen == 16) {
                char ipBuf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, payload + offset, ipBuf, INET6_ADDRSTRLEN);
                ans.data = ipBuf;
                info.answers.push_back(ans);
            } else if (atype == 5) {
                size_t cnameOffset = offset;
                std::string cname;
                if (readDnsName(payload, len, cnameOffset, cname)) {
                    ans.data = cname;
                    info.answers.push_back(ans);
                }
            }

            offset += ardlen;
        }
    }

    return info;
}

// ==========================================
// Signal Handling & Teardown
// ==========================================
void signalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        std::cout << "\n" << clr.b_yellow << "[!] Operation interrupted by user (SIGINT)." << clr.reset << "\n";
        if (g_pcap_handle != nullptr) {
            pcap_breakloop(g_pcap_handle);
        }
    }
}

// ==========================================
// Packet Processing Callback
// ==========================================
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    (void)userData;
    stats.totalPackets++;
    stats.totalBytes += pkthdr->len;

    if (g_pcap_dumper != nullptr) {
        pcap_dump(reinterpret_cast<u_char*>(g_pcap_dumper), pkthdr, packet);
    }

    if (pkthdr->caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* ethHeader = reinterpret_cast<const EthernetHeader*>(packet);
    uint16_t etherType = ntohs(ethHeader->ether_type);

    std::cout << clr.dim << "[" << std::setw(5) << std::setfill(' ') << stats.totalPackets << "] "
              << clr.reset;

    if (etherType == ETHERTYPE_ARP) {
        stats.arpPackets++;
        if (pkthdr->caplen >= sizeof(EthernetHeader) + sizeof(ARPHeader)) {
            const ARPHeader* arp = reinterpret_cast<const ARPHeader*>(packet + sizeof(EthernetHeader));
            uint16_t op = ntohs(arp->ar_op);
            char spa[INET_ADDRSTRLEN], tpa[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(arp->ar_spa), spa, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(arp->ar_tpa), tpa, INET_ADDRSTRLEN);

            std::cout << clr.b_yellow << "[ARP] " << clr.reset;
            if (op == ARPOP_REQUEST) {
                std::cout << "Who has " << clr.bold << tpa << clr.reset
                          << "? Tell " << spa << " (" << formatMac(arp->ar_sha) << ")";
            } else if (op == ARPOP_REPLY) {
                std::cout << spa << " is at " << clr.bold << formatMac(arp->ar_sha) << clr.reset;
            } else {
                std::cout << "Opcode " << op << " from " << spa << " to " << tpa;
            }
            std::cout << " | " << pkthdr->len << " B\n";
        }
        return;
    }

    if (etherType != ETHERTYPE_IP) {
        stats.otherPackets++;
        std::cout << clr.dim << "[Eth 0x" << std::hex << etherType << std::dec << "] "
                  << formatMac(ethHeader->ether_shost) << " -> "
                  << formatMac(ethHeader->ether_dhost)
                  << " | " << pkthdr->len << " B" << clr.reset << "\n";
        return;
    }

    if (pkthdr->caplen < sizeof(EthernetHeader) + sizeof(IPHeader)) return;

    const IPHeader* ip = reinterpret_cast<const IPHeader*>(packet + sizeof(EthernetHeader));
    int ipHeaderLen = (ip->ip_vhl & 0x0F) * 4;
    if (ipHeaderLen < 20) return;

    char srcIp[INET_ADDRSTRLEN], dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dstIp, INET_ADDRSTRLEN);

    const u_char* l4Packet = packet + sizeof(EthernetHeader) + ipHeaderLen;
    size_t l4Len = (pkthdr->caplen > sizeof(EthernetHeader) + ipHeaderLen)
                   ? (pkthdr->caplen - sizeof(EthernetHeader) - ipHeaderLen)
                   : 0;

    switch (ip->ip_p) {
        case IPPROTO_TCP: {
            stats.tcpPackets++;
            if (l4Len >= sizeof(TCPHeader)) {
                const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(l4Packet);
                uint16_t sport = ntohs(tcp->th_sport);
                uint16_t dport = ntohs(tcp->th_dport);
                int tcpHeaderLen = ((tcp->th_offx2 >> 4) & 0x0F) * 4;
                int payloadLen = static_cast<int>(l4Len) - tcpHeaderLen;
                if (payloadLen < 0) payloadLen = 0;

                std::string sService = getServiceName(sport);
                std::string dService = getServiceName(dport);
                std::string svcInfo;
                if (!sService.empty()) svcInfo = " (" + sService + ")";
                else if (!dService.empty()) svcInfo = " (" + dService + ")";

                const uint8_t* tcpPayload = l4Packet + tcpHeaderLen;
                HttpInfo http = parseHttp(tcpPayload, payloadLen);

                DnsInfo dns;
                if ((sport == 53 || dport == 53) && payloadLen > 2) {
                    dns = parseDns(tcpPayload + 2, payloadLen - 2);
                }

                if (http.isHttp) {
                    stats.httpPackets++;
                    std::cout << clr.b_green << "[HTTP] " << clr.reset
                              << srcIp << ":" << clr.bold << sport << clr.reset << " -> "
                              << dstIp << ":" << clr.bold << dport << clr.reset
                              << " | " << (http.isRequest ? clr.b_cyan : clr.b_yellow)
                              << http.startLine << clr.reset << "\n";

                    if (!http.host.empty()) {
                        std::cout << "       " << clr.dim << "Host: " << clr.reset << http.host;
                    }
                    if (!http.userAgent.empty()) {
                        std::cout << " " << clr.dim << "| UA: " << clr.reset << http.userAgent;
                    }
                    if (!http.contentType.empty()) {
                        std::cout << " " << clr.dim << "| Type: " << clr.reset << http.contentType;
                    }
                    if (!http.server.empty()) {
                        std::cout << " " << clr.dim << "| Server: " << clr.reset << http.server;
                    }
                    if (!http.host.empty() || !http.contentType.empty() || !http.server.empty()) {
                        std::cout << "\n";
                    }
                } else if (dns.isDns) {
                    stats.dnsPackets++;
                    std::cout << clr.b_cyan << "[DNS/TCP] " << clr.reset
                              << srcIp << ":" << sport << " -> " << dstIp << ":" << dport
                              << " | " << (dns.isResponse ? "Response: " : "Query: ")
                              << clr.b_white << dns.queryName << clr.reset
                              << " [" << dns.queryType << "] (TxID: 0x" << std::hex << dns.txId << std::dec << ")\n";
                } else {
                    std::cout << clr.b_cyan << "[TCP] " << clr.reset
                              << srcIp << ":" << clr.bold << sport << clr.reset << " -> "
                              << dstIp << ":" << clr.bold << dport << clr.reset
                              << clr.dim << svcInfo << clr.reset
                              << " | Flags: [" << clr.b_white << formatTcpFlags(tcp->th_flags) << clr.reset << "]"
                              << " | Data: " << payloadLen << " B"
                              << " | Total: " << pkthdr->len << " B\n";
                }

                if (cfg.verbose) {
                    std::cout << clr.dim << "       Seq: " << ntohl(tcp->th_seq)
                              << " | Ack: " << ntohl(tcp->th_ack)
                              << " | Win: " << ntohs(tcp->th_win)
                              << " | TTL: " << static_cast<int>(ip->ip_ttl)
                              << clr.reset << "\n";
                }

                if (cfg.showHex && payloadLen > 0) {
                    printHexAscii(tcpPayload, payloadLen);
                }
            } else {
                std::cout << clr.b_cyan << "[TCP] " << clr.reset << srcIp << " -> " << dstIp
                          << " | " << pkthdr->len << " B\n";
            }
            break;
        }

        case IPPROTO_UDP: {
            stats.udpPackets++;
            if (l4Len >= sizeof(UDPHeader)) {
                const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(l4Packet);
                uint16_t sport = ntohs(udp->uh_sport);
                uint16_t dport = ntohs(udp->uh_dport);
                int udpDataLen = static_cast<int>(l4Len) - sizeof(UDPHeader);
                if (udpDataLen < 0) udpDataLen = 0;

                std::string sService = getServiceName(sport);
                std::string dService = getServiceName(dport);
                std::string svcInfo;
                if (!sService.empty()) svcInfo = " (" + sService + ")";
                else if (!dService.empty()) svcInfo = " (" + dService + ")";

                const uint8_t* udpPayload = l4Packet + sizeof(UDPHeader);

                DnsInfo dns;
                if (sport == 53 || dport == 53 || sport == 5353 || dport == 5353 ||
                    sport == 5355 || dport == 5355) {
                    dns = parseDns(udpPayload, udpDataLen);
                }

                if (dns.isDns) {
                    stats.dnsPackets++;
                    std::cout << clr.b_cyan << "[DNS] " << clr.reset
                              << srcIp << ":" << clr.bold << sport << clr.reset << " -> "
                              << dstIp << ":" << clr.bold << dport << clr.reset;

                    if (dns.isResponse) {
                        std::cout << " | " << clr.b_green << "Response: " << clr.reset
                                  << clr.b_white << dns.queryName << clr.reset
                                  << " (" << dns.rcode << ")";

                        if (!dns.answers.empty()) {
                            std::cout << " -> ";
                            for (size_t i = 0; i < dns.answers.size(); ++i) {
                                if (i > 0) std::cout << ", ";
                                std::cout << clr.bold << dns.answers[i].data << clr.reset
                                          << " (" << dns.answers[i].type << ")";
                            }
                        }
                    } else {
                        std::cout << " | " << clr.b_yellow << "Query: " << clr.reset
                                  << clr.b_white << dns.queryName << clr.reset
                                  << " [" << dns.queryType << "]";
                    }

                    std::cout << " | TxID: 0x" << std::hex << dns.txId << std::dec
                              << " | " << pkthdr->len << " B\n";
                } else {
                    std::cout << clr.b_green << "[UDP] " << clr.reset
                              << srcIp << ":" << clr.bold << sport << clr.reset << " -> "
                              << dstIp << ":" << clr.bold << dport << clr.reset
                              << clr.dim << svcInfo << clr.reset
                              << " | Length: " << ntohs(udp->uh_ulen) << " B"
                              << " | Total: " << pkthdr->len << " B\n";
                }

                if (cfg.showHex && udpDataLen > 0) {
                    printHexAscii(udpPayload, udpDataLen);
                }
            } else {
                std::cout << clr.b_green << "[UDP] " << clr.reset << srcIp << " -> " << dstIp
                          << " | " << pkthdr->len << " B\n";
            }
            break;
        }

        case IPPROTO_ICMP: {
            stats.icmpPackets++;
            if (l4Len >= sizeof(ICMPHeader)) {
                const ICMPHeader* icmp = reinterpret_cast<const ICMPHeader*>(l4Packet);
                std::string typeStr = "Type " + std::to_string(icmp->icmp_type);
                if (icmp->icmp_type == 8)      typeStr = "Echo Request (Ping)";
                else if (icmp->icmp_type == 0) typeStr = "Echo Reply (Ping)";
                else if (icmp->icmp_type == 3) typeStr = "Dest Unreachable";
                else if (icmp->icmp_type == 11)typeStr = "Time Exceeded";

                std::cout << clr.b_yellow << "[ICMP] " << clr.reset
                          << srcIp << " -> " << dstIp
                          << " | " << clr.bold << typeStr << clr.reset
                          << " (Code " << static_cast<int>(icmp->icmp_code) << ")"
                          << " | Total: " << pkthdr->len << " B\n";
            } else {
                std::cout << clr.b_yellow << "[ICMP] " << clr.reset << srcIp << " -> " << dstIp
                          << " | " << pkthdr->len << " B\n";
            }
            break;
        }

        default:
            stats.otherPackets++;
            std::cout << clr.b_magenta << "[IP " << static_cast<int>(ip->ip_p) << "] " << clr.reset
                      << srcIp << " -> " << dstIp
                      << " | Total: " << pkthdr->len << " B\n";
            break;
    }
}

// ==========================================
// Interface Listing Helper
// ==========================================
struct DeviceEntry {
    int index;
    std::string name;
    std::string description;
    bool isLoopback;
    std::vector<std::string> ips;
};

std::vector<DeviceEntry> getDeviceList(char* errbuf) {
    std::vector<DeviceEntry> list;
    pcap_if_t* devs = nullptr;

    if (pcap_findalldevs(&devs, errbuf) == -1 || devs == nullptr) {
        return list;
    }

    int idx = 1;
    for (pcap_if_t* d = devs; d != nullptr; d = d->next, ++idx) {
        DeviceEntry entry;
        entry.index = idx;
        entry.name = d->name ? d->name : "";
        entry.description = d->description ? d->description : "";
        entry.isLoopback = (d->flags & PCAP_IF_LOOPBACK) != 0;

        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(a->addr);
                char ipBuf[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &(sa->sin_addr), ipBuf, INET_ADDRSTRLEN)) {
                    entry.ips.push_back(ipBuf);
                }
            }
        }
        list.push_back(entry);
    }

    pcap_freealldevs(devs);
    return list;
}

// ==========================================
// MODULE 2: Website Security & OWASP Header Auditor
// ==========================================
void parseHostUrl(const std::string& input, std::string& outHost, int& outPort, std::string& outPath) {
    std::string s = input;
    outPort = 80;
    outPath = "/";

    if (s.rfind("http://", 0) == 0) {
        s = s.substr(7);
        outPort = 80;
    } else if (s.rfind("https://", 0) == 0) {
        s = s.substr(8);
        outPort = 443;
    }

    size_t slashPos = s.find('/');
    if (slashPos != std::string::npos) {
        outPath = s.substr(slashPos);
        s = s.substr(0, slashPos);
    }

    size_t colonPos = s.find(':');
    if (colonPos != std::string::npos) {
        outHost = s.substr(0, colonPos);
        try {
            outPort = std::stoi(s.substr(colonPos + 1));
        } catch (...) {}
    } else {
        outHost = s;
    }
}

void auditWebsite(const std::string& target) {
    std::string host, path;
    int port = 80;
    parseHostUrl(target, host, port, path);

    std::cout << "\n" << clr.b_cyan
              << "================================================================\n"
              << "       ASTA-SEC WEBSITE SECURITY AUDITOR (OWASP / NESSUS)       \n"
              << "================================================================\n" << clr.reset;
    std::cout << "[*] Target Host : " << clr.b_white << host << clr.reset << "\n";
    std::cout << "[*] Port        : " << port << " (HTTP Probe)\n";
    std::cout << "[*] Path        : " << path << "\n";
    std::cout << clr.dim << "----------------------------------------------------------------\n" << clr.reset;

    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || res == nullptr) {
        std::cerr << clr.b_red << "[!] Failed to resolve hostname: " << host << clr.reset << "\n";
        return;
    }

    char ipStr[INET_ADDRSTRLEN];
    struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &(sa->sin_addr), ipStr, INET_ADDRSTRLEN);
    std::cout << "[+] Resolved IP : " << clr.b_green << ipStr << clr.reset << "\n";

    socket_t sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (IS_INVALID_SOCKET(sock)) {
        std::cerr << clr.b_red << "[!] Failed to create socket.\n" << clr.reset;
        freeaddrinfo(res);
        return;
    }

    // Set connection timeout (3 seconds)
#ifdef _WIN32
    DWORD timeout = 3000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif

    auto connectStart = std::chrono::steady_clock::now();
    if (connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        std::cerr << clr.b_red << "[!] Connection failed or timed out to " << host << ":" << port << clr.reset << "\n";
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return;
    }
    auto connectEnd = std::chrono::steady_clock::now();
    double latencyMs = std::chrono::duration<double, std::milli>(connectEnd - connectStart).count();
    std::cout << "[+] TCP Latency : " << std::fixed << std::setprecision(1) << latencyMs << " ms\n\n";

    freeaddrinfo(res);

    // Send HTTP Request
    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: " + host + "\r\n"
                      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AstaSec-Auditor/2.0\r\n"
                      "Accept: text/html,*/*\r\n"
                      "Connection: close\r\n\r\n";

    send(sock, req.c_str(), static_cast<int>(req.length()), 0);

    // Read Response Headers
    std::string response;
    char buffer[4096];
    int bytesRead = 0;
    while ((bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesRead] = '\0';
        response.append(buffer, bytesRead);
        if (response.find("\r\n\r\n") != std::string::npos) break;
    }
    CLOSE_SOCKET(sock);

    if (response.empty()) {
        std::cerr << clr.b_red << "[!] No response received from server.\n" << clr.reset;
        return;
    }

    // Parse Headers
    std::istringstream respStream(response);
    std::string statusLine;
    std::getline(respStream, statusLine);
    if (!statusLine.empty() && statusLine.back() == '\r') statusLine.pop_back();

    std::map<std::string, std::string> headers;
    std::string headerLine;
    while (std::getline(respStream, headerLine) && !headerLine.empty() && headerLine != "\r") {
        if (!headerLine.empty() && headerLine.back() == '\r') headerLine.pop_back();
        size_t colon = headerLine.find(':');
        if (colon != std::string::npos) {
            std::string key = headerLine.substr(0, colon);
            std::string val = headerLine.substr(colon + 1);
            while (!val.empty() && val[0] == ' ') val.erase(0, 1);
            std::string lowerKey = key;
            std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
            headers[lowerKey] = val;
        }
    }

    std::cout << clr.bold << "HTTP Response Status: " << clr.reset
              << clr.b_cyan << statusLine << clr.reset << "\n\n";

    std::cout << clr.bold << "--- OWASP Security Headers Assessment ---\n" << clr.reset;

    int score = 0;
    std::vector<std::string> recommendations;

    // 1. Strict-Transport-Security (HSTS)
    if (headers.count("strict-transport-security")) {
        score += 25;
        std::cout << "  " << clr.b_green << "[PASS]" << clr.reset
                  << " Strict-Transport-Security (HSTS): " << headers["strict-transport-security"] << "\n";
    } else {
        std::cout << "  " << clr.b_red << "[FAIL]" << clr.reset
                  << " Strict-Transport-Security (HSTS) is MISSING.\n";
        recommendations.push_back("Enable HSTS to prevent SSL stripping (e.g., Strict-Transport-Security: max-age=31536000; includeSubDomains).");
    }

    // 2. Content-Security-Policy (CSP)
    if (headers.count("content-security-policy")) {
        score += 25;
        std::cout << "  " << clr.b_green << "[PASS]" << clr.reset
                  << " Content-Security-Policy (CSP): Present\n";
    } else {
        std::cout << "  " << clr.b_red << "[FAIL]" << clr.reset
                  << " Content-Security-Policy (CSP) is MISSING.\n";
        recommendations.push_back("Deploy Content-Security-Policy (CSP) to restrict untrusted scripts and prevent XSS injection.");
    }

    // 3. X-Frame-Options (Clickjacking defense)
    if (headers.count("x-frame-options")) {
        score += 15;
        std::cout << "  " << clr.b_green << "[PASS]" << clr.reset
                  << " X-Frame-Options: " << headers["x-frame-options"] << "\n";
    } else {
        std::cout << "  " << clr.b_red << "[FAIL]" << clr.reset
                  << " X-Frame-Options is MISSING.\n";
        recommendations.push_back("Set X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking iframe attacks.");
    }

    // 4. X-Content-Type-Options
    if (headers.count("x-content-type-options")) {
        score += 15;
        std::cout << "  " << clr.b_green << "[PASS]" << clr.reset
                  << " X-Content-Type-Options: " << headers["x-content-type-options"] << "\n";
    } else {
        std::cout << "  " << clr.b_red << "[FAIL]" << clr.reset
                  << " X-Content-Type-Options is MISSING.\n";
        recommendations.push_back("Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing vulnerabilities.");
    }

    // 5. Referrer-Policy
    if (headers.count("referrer-policy")) {
        score += 10;
        std::cout << "  " << clr.b_green << "[PASS]" << clr.reset
                  << " Referrer-Policy: " << headers["referrer-policy"] << "\n";
    } else {
        std::cout << "  " << clr.b_yellow << "[WARN]" << clr.reset
                  << " Referrer-Policy is MISSING.\n";
        recommendations.push_back("Set Referrer-Policy: strict-origin-when-cross-origin to prevent leakage of private URLs.");
    }

    // 6. Permissions-Policy
    if (headers.count("permissions-policy")) {
        score += 10;
        std::cout << "  " << clr.b_green << "[PASS]" << clr.reset
                  << " Permissions-Policy: Present\n";
    } else {
        std::cout << "  " << clr.b_yellow << "[WARN]" << clr.reset
                  << " Permissions-Policy is MISSING.\n";
    }

    // 7. Information Disclosure (Server / X-Powered-By)
    std::cout << "\n" << clr.bold << "--- Information Disclosure Inspection ---\n" << clr.reset;
    if (headers.count("server")) {
        std::cout << "  " << clr.b_yellow << "[INFO]" << clr.reset
                  << " Server Banner Exposed: " << headers["server"] << "\n";
        if (headers["server"].find('/') != std::string::npos) {
            score -= 5;
            recommendations.push_back("Mask detailed web server versions in the 'Server' header to hinder targeted version exploits.");
        }
    }
    if (headers.count("x-powered-by")) {
        std::cout << "  " << clr.b_red << "[WARN]" << clr.reset
                  << " X-Powered-By Exposed: " << headers["x-powered-by"] << "\n";
        score -= 10;
        recommendations.push_back("Disable 'X-Powered-By' header in your web framework to prevent technology stack fingerprinting.");
    }

    if (score < 0) score = 0;
    if (score > 100) score = 100;

    std::string grade = "F";
    std::string gradeColor = clr.b_red;
    if (score >= 90) { grade = "A+"; gradeColor = clr.b_green; }
    else if (score >= 80) { grade = "A"; gradeColor = clr.b_green; }
    else if (score >= 70) { grade = "B"; gradeColor = clr.b_cyan; }
    else if (score >= 55) { grade = "C"; gradeColor = clr.b_yellow; }
    else if (score >= 40) { grade = "D"; gradeColor = clr.yellow; }

    std::cout << "\n" << clr.dim << "----------------------------------------------------------------\n" << clr.reset;
    std::cout << "  Defensive Security Score : " << gradeColor << score << "/100" << clr.reset << "\n";
    std::cout << "  Overall Security Grade   : " << gradeColor << "[" << grade << "]" << clr.reset << "\n";
    std::cout << clr.dim << "----------------------------------------------------------------\n" << clr.reset;

    if (!recommendations.empty()) {
        std::cout << clr.bold << "\nRemediation Recommendations:\n" << clr.reset;
        for (size_t i = 0; i < recommendations.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << recommendations[i] << "\n";
        }
    }
    std::cout << "\n";
}

// ==========================================
// MODULE 3: Host & Port Scanner (Nmap style)
// ==========================================
void scanPorts(const std::string& targetHost) {
    std::string host, path;
    int dummyPort = 80;
    parseHostUrl(targetHost, host, dummyPort, path);

    std::cout << "\n" << clr.b_cyan
              << "================================================================\n"
              << "          ASTA-SEC PORT & SERVICE SCANNER (NMAP STYLE)          \n"
              << "================================================================\n" << clr.reset;
    std::cout << "[*] Target Host : " << clr.b_white << host << clr.reset << "\n";

    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), "80", &hints, &res) != 0 || res == nullptr) {
        std::cerr << clr.b_red << "[!] Unable to resolve target host: " << host << clr.reset << "\n";
        return;
    }

    char ipStr[INET_ADDRSTRLEN];
    struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &(sa->sin_addr), ipStr, INET_ADDRSTRLEN);
    std::cout << "[*] Target IP   : " << clr.b_green << ipStr << clr.reset << "\n";
    std::cout << clr.dim << "----------------------------------------------------------------\n" << clr.reset;
    std::cout << clr.bold << " PORT     STATE    SERVICE       LATENCY\n" << clr.reset;
    std::cout << clr.dim  << " ----     -----    -------       -------\n" << clr.reset;

    freeaddrinfo(res);

    // Standard list of critical network / web ports
    std::vector<int> portsToCheck = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443};

    int openCount = 0;

    for (int p : portsToCheck) {
        struct sockaddr_in targetAddr;
        std::memset(&targetAddr, 0, sizeof(targetAddr));
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(p);
        inet_pton(AF_INET, ipStr, &targetAddr.sin_addr);

        socket_t s = socket(AF_INET, SOCK_STREAM, 0);
        if (IS_INVALID_SOCKET(s)) continue;

        // Set non-blocking mode for fast sub-second timeouts
#ifdef _WIN32
        u_long nonblock = 1;
        ioctlsocket(s, FIONBIO, &nonblock);
#else
        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

        auto t0 = std::chrono::steady_clock::now();
        connect(s, (struct sockaddr*)&targetAddr, sizeof(targetAddr));

        fd_set writeFds, errFds;
        FD_ZERO(&writeFds);
        FD_ZERO(&errFds);
        FD_SET(s, &writeFds);
        FD_SET(s, &errFds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 400000; // 400 ms timeout per port

        int sel = select(static_cast<int>(s + 1), nullptr, &writeFds, &errFds, &tv);
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        std::string svc = getServiceName(p);
        if (svc.empty()) svc = "unknown";

        if (sel > 0 && FD_ISSET(s, &writeFds)) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
            if (so_error == 0) {
                openCount++;
                std::cout << " " << std::left << std::setw(8) << (std::to_string(p) + "/tcp")
                          << clr.b_green << std::setw(9) << "OPEN" << clr.reset
                          << std::setw(14) << svc
                          << std::fixed << std::setprecision(1) << ms << " ms\n" << std::flush;
            }
        }
        CLOSE_SOCKET(s);
    }

    std::cout << clr.dim << "----------------------------------------------------------------\n" << clr.reset;
    std::cout << "[*] Scan complete: " << clr.b_white << openCount << " open port(s)" << clr.reset
              << " detected out of " << portsToCheck.size() << " scanned.\n\n";
}

// ==========================================
// MODULE 5: DNS Query & Resolver Tool
// ==========================================
void queryDnsRecord(const std::string& domain) {
    std::cout << "\n" << clr.b_cyan
              << "================================================================\n"
              << "                   ASTA-SEC DNS LOOKUP TOOL                    \n"
              << "================================================================\n" << clr.reset;
    std::cout << "[*] Querying Domain : " << clr.b_white << domain << clr.reset << "\n\n";

    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) {
        std::cerr << clr.b_red << "[!] DNS Lookup failed for " << domain << clr.reset << "\n\n";
        return;
    }

    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            char ipBuf[INET_ADDRSTRLEN];
            struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipBuf, INET_ADDRSTRLEN);
            std::cout << "  " << clr.b_green << "[A Record]   " << clr.reset << ipBuf << "\n";
        } else if (p->ai_family == AF_INET6) {
            char ipBuf[INET6_ADDRSTRLEN];
            struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipBuf, INET6_ADDRSTRLEN);
            std::cout << "  " << clr.b_cyan << "[AAAA Record]" << clr.reset << ipBuf << "\n";
        }
    }
    freeaddrinfo(res);
    std::cout << "\n";
}

// ==========================================
// MODULE 6: Subdomain Enumeration & Analysis
// ==========================================
void searchSubdomains(const std::string& rootDomain) {
    std::string domain = rootDomain;
    if (domain.rfind("http://", 0) == 0) domain = domain.substr(7);
    else if (domain.rfind("https://", 0) == 0) domain = domain.substr(8);
    size_t slash = domain.find('/');
    if (slash != std::string::npos) domain = domain.substr(0, slash);

    std::cout << "\n" << clr.b_cyan
              << "================================================================\n"
              << "          ASTA-SEC SUBDOMAIN SEARCH & ATTACK SURFACE            \n"
              << "================================================================\n" << clr.reset;
    std::cout << "[*] Root Domain : " << clr.b_white << domain << clr.reset << "\n";
    std::cout << "[*] Enumerating active DNS subdomains & web endpoints...\n\n";

    std::vector<std::string> prefixes = {
        "www", "mail", "api", "dev", "staging", "test", "admin", "portal", "vpn",
        "app", "auth", "login", "sso", "cdn", "cloud", "shop", "blog", "support",
        "docs", "status", "beta", "git", "dashboard", "monitor", "grafana", "m",
        "mobile", "corp", "internal", "secure", "remote", "gateway", "pay"
    };

    std::cout << clr.bold << " SUBDOMAIN                      IP ADDRESS          HTTP STATUS\n" << clr.reset;
    std::cout << clr.dim  << " ---------                      ----------          -----------\n" << clr.reset;

    int foundCount = 0;

    for (const auto& prefix : prefixes) {
        std::string fqdn = prefix + "." + domain;

        struct addrinfo hints, *res = nullptr;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(fqdn.c_str(), "80", &hints, &res) == 0 && res != nullptr) {
            foundCount++;
            char ipStr[INET_ADDRSTRLEN];
            struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
            inet_ntop(AF_INET, &(sa->sin_addr), ipStr, INET_ADDRSTRLEN);

            std::string statusStr = "No Web";
            socket_t s = socket(AF_INET, SOCK_STREAM, 0);
            if (!IS_INVALID_SOCKET(s)) {
#ifdef _WIN32
                DWORD timeout = 1200;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 200000;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
                if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) == 0) {
                    std::string req = "HEAD / HTTP/1.1\r\nHost: " + fqdn + "\r\nConnection: close\r\n\r\n";
                    send(s, req.c_str(), static_cast<int>(req.length()), 0);
                    char buf[128];
                    int r = recv(s, buf, sizeof(buf) - 1, 0);
                    if (r > 0) {
                        buf[r] = '\0';
                        std::string resp(buf);
                        size_t space1 = resp.find(' ');
                        if (space1 != std::string::npos && space1 + 4 <= resp.length()) {
                            statusStr = resp.substr(space1 + 1, 3);
                            if (statusStr == "200") statusStr = clr.b_green + statusStr + " OK" + clr.reset;
                            else if (statusStr[0] == '3') statusStr = clr.b_cyan + statusStr + " Redirect" + clr.reset;
                            else if (statusStr == "403" || statusStr == "401") statusStr = clr.b_yellow + statusStr + " Forbidden" + clr.reset;
                            else if (statusStr == "404") statusStr = clr.b_red + statusStr + " Not Found" + clr.reset;
                        }
                    }
                }
                CLOSE_SOCKET(s);
            }

            std::string subCol = fqdn.length() > 30 ? fqdn.substr(0, 27) + "..." : fqdn;
            std::cout << " " << clr.b_white << std::left << std::setw(31) << subCol << clr.reset
                      << clr.cyan << std::setw(20) << ipStr << clr.reset
                      << statusStr << "\n" << std::flush;

            freeaddrinfo(res);
        }
    }

    std::cout << clr.dim << "----------------------------------------------------------------\n" << clr.reset;
    std::cout << "[*] Recon complete: " << clr.b_white << foundCount << " active subdomain(s)" << clr.reset
              << " identified out of " << prefixes.size() << " probed.\n\n";
}

// ==========================================
// MODULE 1: Packet Sniffer Execution
// ==========================================
int runSniffer() {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::vector<DeviceEntry> devices = getDeviceList(errbuf);

    if (devices.empty()) {
        std::cerr << clr.b_red << "[!] No network devices found: " << errbuf << clr.reset << "\n";
        std::cerr << clr.dim   << "    Ensure Npcap / libpcap is installed and running with elevated privileges.\n" << clr.reset;
        return 1;
    }

    std::string targetDevice;
    if (!cfg.interfaceName.empty()) {
        try {
            int reqIdx = std::stoi(cfg.interfaceName);
            for (const auto& d : devices) {
                if (d.index == reqIdx) {
                    targetDevice = d.name;
                    break;
                }
            }
        } catch (...) {}

        if (targetDevice.empty()) {
            targetDevice = cfg.interfaceName;
        }
    } else {
        for (const auto& d : devices) {
            if (!d.isLoopback && !d.ips.empty()) {
                targetDevice = d.name;
                break;
            }
        }
        if (targetDevice.empty()) {
            for (const auto& d : devices) {
                if (!d.isLoopback) {
                    targetDevice = d.name;
                    break;
                }
            }
        }
        if (targetDevice.empty()) {
            targetDevice = devices[0].name;
        }
    }

    std::cout << clr.b_white << "[*] Device Target : " << clr.b_cyan << targetDevice << clr.reset << "\n";
    std::cout << clr.b_white << "[*] BPF Filter    : " << clr.b_yellow << cfg.filter << clr.reset << "\n";
    if (!cfg.pcapOutputFile.empty()) {
        std::cout << clr.b_white << "[*] PCAP Output   : " << clr.b_green << cfg.pcapOutputFile << clr.reset << "\n";
    }
    if (cfg.maxPackets > 0) {
        std::cout << clr.b_white << "[*] Packet Limit  : " << cfg.maxPackets << "\n";
    }
    std::cout << clr.dim << "----------------------------------------------------------------\n" << clr.reset;

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    pcap_t* handle = pcap_open_live(targetDevice.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << clr.b_red << "[!] Failed to open interface " << targetDevice << ": "
                  << errbuf << clr.reset << "\n";
        std::cerr << clr.dim   << "    Requires administrator privileges or setcap capabilities.\n" << clr.reset;
        return 1;
    }
    g_pcap_handle = handle;

    if (!cfg.pcapOutputFile.empty()) {
        g_pcap_dumper = pcap_dump_open(handle, cfg.pcapOutputFile.c_str());
        if (!g_pcap_dumper) {
            std::cerr << clr.b_red << "[!] Failed to create PCAP dump file: "
                      << pcap_geterr(handle) << clr.reset << "\n";
        }
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, cfg.filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << clr.b_red << "[!] BPF filter syntax error: " << pcap_geterr(handle) << clr.reset << "\n";
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << clr.b_red << "[!] Failed to apply filter: " << pcap_geterr(handle) << clr.reset << "\n";
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    std::cout << clr.b_green << "[+] Sniffing live traffic... Press Ctrl+C to stop.\n\n" << clr.reset;
    stats.startTime = std::chrono::steady_clock::now();

    pcap_loop(handle, static_cast<int>(cfg.maxPackets), packetHandler, nullptr);

    auto endTime = std::chrono::steady_clock::now();
    double durationSec = std::chrono::duration<double>(endTime - stats.startTime).count();

    struct pcap_stat ps;
    uint32_t kernelRecv = 0, kernelDrop = 0;
    if (pcap_stats(handle, &ps) >= 0) {
        kernelRecv = ps.ps_recv;
        kernelDrop = ps.ps_drop;
    }

    std::cout << "\n" << clr.b_cyan
              << "===================== ASTA-SEC SUMMARY =====================\n" << clr.reset;
    std::cout << "  Duration         : " << std::fixed << std::setprecision(2) << durationSec << " s\n";
    std::cout << "  Captured Packets : " << clr.b_white << stats.totalPackets << clr.reset << "\n";
    std::cout << "    - TCP          : " << clr.cyan << stats.tcpPackets << clr.reset << "\n";
    std::cout << "    - UDP          : " << clr.green << stats.udpPackets << clr.reset << "\n";
    std::cout << "    - HTTP Detected: " << clr.b_green << stats.httpPackets << clr.reset << "\n";
    std::cout << "    - DNS Detected : " << clr.b_cyan << stats.dnsPackets << clr.reset << "\n";
    std::cout << "    - ICMP         : " << clr.yellow << stats.icmpPackets << clr.reset << "\n";
    std::cout << "    - ARP          : " << clr.yellow << stats.arpPackets << clr.reset << "\n";
    std::cout << "    - Other        : " << stats.otherPackets << "\n";
    std::cout << "  Total Bytes      : " << stats.totalBytes << " bytes\n";
    if (kernelRecv > 0 || kernelDrop > 0) {
        std::cout << "  Kernel Received  : " << kernelRecv << "\n";
        std::cout << "  Kernel Dropped   : " << (kernelDrop > 0 ? clr.b_red : "") << kernelDrop << clr.reset << "\n";
    }
    if (g_pcap_dumper != nullptr) {
        std::cout << "  Dump File Saved  : " << clr.b_green << cfg.pcapOutputFile << clr.reset << "\n";
        pcap_dump_close(g_pcap_dumper);
        g_pcap_dumper = nullptr;
    }
    std::cout << clr.b_cyan
              << "============================================================\n" << clr.reset;

    pcap_freecode(&fp);
    pcap_close(handle);
    g_pcap_handle = nullptr;

    return 0;
}

// ==========================================
// ANTIGRAVITY-STYLE INTERACTIVE MENU (TUI)
// ==========================================
void runInteractiveMenu() {
    while (true) {
        printBanner();
        std::cout << clr.bold << "SELECT MODULE:\n" << clr.reset;
        std::cout << "  " << clr.b_cyan  << "[1]" << clr.reset << " Live Packet Sniffer (libpcap / Npcap Engine)\n";
        std::cout << "  " << clr.b_green << "[2]" << clr.reset << " Website Security & Header Auditor (OWASP / Nessus)\n";
        std::cout << "  " << clr.b_yellow<< "[3]" << clr.reset << " Subdomain Search & Attack Surface Recon (DNS + Web)\n";
        std::cout << "  " << clr.b_cyan  << "[4]" << clr.reset << " Host & Port Connectivity Scanner (Nmap-style)\n";
        std::cout << "  " << clr.b_magenta<<"[5]" << clr.reset << " DNS Resolver & Domain Query Tool\n";
        std::cout << "  " << clr.b_white << "[6]" << clr.reset << " List & Inspect Available Network Interfaces\n";
        std::cout << "  " << clr.dim     << "[0]" << clr.reset << " Exit Asta-Sec Suite\n";
        std::cout << clr.dim << "----------------------------------------------------------------\n" << clr.reset;
        std::cout << clr.b_white << "asta-sec > " << clr.reset;

        std::string choice;
        if (!std::getline(std::cin, choice)) break;

        if (choice == "0" || choice == "exit" || choice == "quit") {
            std::cout << "\n[*] Exiting Asta-Sec Suite. Goodbye!\n";
            break;
        } else if (choice == "1") {
            char errbuf[PCAP_ERRBUF_SIZE];
            std::vector<DeviceEntry> devs = getDeviceList(errbuf);
            std::cout << "\nAvailable Interfaces:\n";
            for (const auto& d : devs) {
                std::cout << "  [" << d.index << "] " << d.name;
                if (!d.description.empty()) std::cout << " (" << d.description << ")";
                std::cout << "\n";
            }
            std::cout << "\nEnter interface index or name [Enter for auto-detect]: ";
            std::string iface;
            std::getline(std::cin, iface);
            cfg.interfaceName = iface;

            std::cout << "Enter BPF filter [e.g. 'ip', 'tcp port 80', 'udp port 53' (default 'ip or arp')]: ";
            std::string filter;
            std::getline(std::cin, filter);
            if (!filter.empty()) cfg.filter = filter;
            else cfg.filter = "ip or arp";

            std::cout << "Enable Hex & ASCII payload dump? (y/N): ";
            std::string hexChoice;
            std::getline(std::cin, hexChoice);
            cfg.showHex = (hexChoice == "y" || hexChoice == "Y");

            std::cout << "Packet limit [0 for continuous]: ";
            std::string limitStr;
            std::getline(std::cin, limitStr);
            try {
                cfg.maxPackets = limitStr.empty() ? 0 : std::stoull(limitStr);
            } catch (...) {
                cfg.maxPackets = 0;
            }

            runSniffer();
        } else if (choice == "2") {
            std::cout << "\nEnter website domain or URL (e.g. google.com, github.com): ";
            std::string target;
            std::getline(std::cin, target);
            if (!target.empty()) {
                auditWebsite(target);
            }
        } else if (choice == "3") {
            std::cout << "\nEnter root domain to analyze (e.g. example.com, github.com): ";
            std::string domain;
            std::getline(std::cin, domain);
            if (!domain.empty()) {
                searchSubdomains(domain);
            }
        } else if (choice == "4") {
            std::cout << "\nEnter target host to scan (e.g. scanme.nmap.org, 127.0.0.1): ";
            std::string host;
            std::getline(std::cin, host);
            if (!host.empty()) {
                scanPorts(host);
            }
        } else if (choice == "5") {
            std::cout << "\nEnter domain name to query (e.g. example.com): ";
            std::string domain;
            std::getline(std::cin, domain);
            if (!domain.empty()) {
                queryDnsRecord(domain);
            }
        } else if (choice == "6") {
            char errbuf[PCAP_ERRBUF_SIZE];
            std::vector<DeviceEntry> devs = getDeviceList(errbuf);
            std::cout << "\nAvailable Interfaces:\n";
            for (const auto& d : devs) {
                std::cout << "  " << clr.b_cyan << "[" << d.index << "] " << clr.reset
                          << clr.bold << d.name << clr.reset;
                if (!d.description.empty()) std::cout << " (" << d.description << ")";
                if (d.isLoopback) std::cout << clr.yellow << " [Loopback]" << clr.reset;
                std::cout << "\n";
                for (const auto& ip : d.ips) {
                    std::cout << "       IPv4: " << clr.green << ip << clr.reset << "\n";
                }
            }
            std::cout << "\n";
        } else {
            std::cout << clr.b_red << "Invalid selection. Please choose 0-6.\n" << clr.reset;
        }

        std::cout << clr.dim << "Press Enter to return to main menu..." << clr.reset;
        std::string pause;
        std::getline(std::cin, pause);
        std::cout << "\n";
    }
}

// ==========================================
// Main CLI Entrypoint
// ==========================================
int main(int argc, char* argv[]) {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[-] Error initializing Winsock.\n";
        return 1;
    }
#endif

    bool runMenu = (argc == 1);

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printBanner();
            printUsage(argv[0]);
#ifdef _WIN32
            WSACleanup();
#endif
            return 0;
        } else if (arg == "-m" || arg == "--menu") {
            runMenu = true;
        } else if (arg == "-l" || arg == "--list") {
            cfg.listInterfacesOnly = true;
        } else if (arg == "-v" || arg == "--verbose") {
            cfg.verbose = true;
        } else if (arg == "-x" || arg == "--hex") {
            cfg.showHex = true;
        } else if (arg == "--no-color") {
            clr.disable();
        } else if (arg == "--audit") {
            if (i + 1 < argc) cfg.auditTarget = argv[++i];
        } else if (arg == "--subdomains") {
            if (i + 1 < argc) cfg.subdomainsTarget = argv[++i];
        } else if (arg == "--scan") {
            if (i + 1 < argc) cfg.scanTarget = argv[++i];
        } else if (arg == "--dns") {
            if (i + 1 < argc) cfg.dnsQueryTarget = argv[++i];
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) cfg.interfaceName = argv[++i];
        } else if (arg == "-f" || arg == "--filter") {
            if (i + 1 < argc) cfg.filter = argv[++i];
        } else if (arg == "-c" || arg == "--count") {
            if (i + 1 < argc) cfg.maxPackets = std::stoull(argv[++i]);
        } else if (arg == "-w" || arg == "--write") {
            if (i + 1 < argc) cfg.pcapOutputFile = argv[++i];
        } else if (arg == "-V" || arg == "--version") {
            std::cout << "asta-sec v2.0.0 (Advanced Security Suite)\n";
#ifdef _WIN32
            WSACleanup();
#endif
            return 0;
        } else {
            if (cfg.interfaceName.empty()) {
                cfg.interfaceName = arg;
            } else {
                cfg.filter = arg;
            }
        }
    }

    if (runMenu) {
        runInteractiveMenu();
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    if (!cfg.auditTarget.empty()) {
        auditWebsite(cfg.auditTarget);
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    if (!cfg.subdomainsTarget.empty()) {
        searchSubdomains(cfg.subdomainsTarget);
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    if (!cfg.scanTarget.empty()) {
        scanPorts(cfg.scanTarget);
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    if (!cfg.dnsQueryTarget.empty()) {
        queryDnsRecord(cfg.dnsQueryTarget);
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    printBanner();

    if (cfg.listInterfacesOnly) {
        char errbuf[PCAP_ERRBUF_SIZE];
        std::vector<DeviceEntry> devices = getDeviceList(errbuf);
        std::cout << clr.bold << "Available Network Interfaces:\n" << clr.reset;
        for (const auto& d : devices) {
            std::cout << "  " << clr.b_cyan << "[" << d.index << "] " << clr.reset
                      << clr.bold << d.name << clr.reset;
            if (!d.description.empty()) std::cout << " (" << d.description << ")";
            if (d.isLoopback) std::cout << clr.yellow << " [Loopback]" << clr.reset;
            std::cout << "\n";
            for (const auto& ip : d.ips) {
                std::cout << "       IPv4: " << clr.green << ip << clr.reset << "\n";
            }
        }
        std::cout << "\n" << clr.dim << "Run with -i <index> or -i <name> to sniff on an interface.\n" << clr.reset;
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    int ret = runSniffer();

#ifdef _WIN32
    WSACleanup();
#endif

    return ret;
}
