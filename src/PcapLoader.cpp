#include "PcapLoader.hpp"

#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>
#include <utility>

namespace pcaproc {

namespace {

// Link-layer constants (avoids dragging extra headers; values come from libpcap).
constexpr int kDltNull = 0;
constexpr int kDltEn10Mb = 1;
constexpr int kDltRaw = 12;
constexpr int kDltLinuxSll = 113;

constexpr std::uint16_t kEthTypeIpv4 = 0x0800;
constexpr std::uint16_t kEthTypeIpv6 = 0x86DD;
constexpr std::uint16_t kEthTypeVlan = 0x8100;
constexpr std::uint16_t kEthTypeQinQ = 0x88A8;

constexpr std::uint8_t kIpProtoUdp = 17;

inline std::uint16_t rd_be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::string ipv4_to_string(const std::uint8_t* p) {
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, p, buf, sizeof(buf));
    return std::string(buf);
}

std::string ipv6_to_string(const std::uint8_t* p) {
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, p, buf, sizeof(buf));
    return std::string(buf);
}

// Parse the UDP header and emit a payload. `udp` points at the UDP header,
// `remaining` is the number of bytes available from there to end of capture.
bool emit_udp(const std::uint8_t* udp, std::size_t remaining,
              std::string src_ip, std::string dst_ip,
              const pcap_pkthdr* hdr,
              const PcapLoader::PayloadCallback& cb) {
    if (remaining < 8) {
        return false;
    }
    const std::uint16_t sport = rd_be16(udp + 0);
    const std::uint16_t dport = rd_be16(udp + 2);
    const std::uint16_t ulen = rd_be16(udp + 4);

    // Payload length per UDP header; clamp to bytes actually captured.
    std::size_t payload_len = (ulen >= 8) ? (ulen - 8u) : 0u;
    const std::size_t avail = remaining - 8u;
    if (payload_len > avail) {
        payload_len = avail;
    }

    UdpPayload out;
    out.ts_sec = static_cast<std::uint64_t>(hdr->ts.tv_sec);
    out.ts_usec = static_cast<std::uint32_t>(hdr->ts.tv_usec);
    out.src_ip = std::move(src_ip);
    out.dst_ip = std::move(dst_ip);
    out.src_port = sport;
    out.dst_port = dport;
    out.data.assign(udp + 8, udp + 8 + payload_len);
    cb(out);
    return true;
}

// Parse an IPv4 packet starting at `ip` with `remaining` bytes available.
bool parse_ipv4(const std::uint8_t* ip, std::size_t remaining,
                const pcap_pkthdr* hdr, const PcapLoader::PayloadCallback& cb) {
    if (remaining < 20) return false;
    const std::uint8_t version = ip[0] >> 4;
    const std::uint8_t ihl = ip[0] & 0x0F;
    if (version != 4 || ihl < 5) return false;
    const std::size_t hdr_len = static_cast<std::size_t>(ihl) * 4u;
    if (hdr_len > remaining) return false;

    const std::uint16_t total_len = rd_be16(ip + 2);
    std::size_t ip_payload_len = remaining - hdr_len;
    if (total_len >= hdr_len && (total_len - hdr_len) < ip_payload_len) {
        ip_payload_len = total_len - hdr_len;
    }

    const std::uint16_t frag = rd_be16(ip + 6);
    const std::uint16_t frag_offset = frag & 0x1FFFu;
    if (frag_offset != 0) {
        // Skip non-first fragments; reassembly is out of scope.
        return false;
    }

    const std::uint8_t proto = ip[9];
    if (proto != kIpProtoUdp) return false;

    return emit_udp(ip + hdr_len, ip_payload_len,
                    ipv4_to_string(ip + 12), ipv4_to_string(ip + 16),
                    hdr, cb);
}

// Walk IPv6 extension headers and return final protocol + offset of transport header.
bool parse_ipv6(const std::uint8_t* ip, std::size_t remaining,
                const pcap_pkthdr* hdr, const PcapLoader::PayloadCallback& cb) {
    constexpr std::size_t kIpv6HdrLen = 40;
    if (remaining < kIpv6HdrLen) return false;
    const std::uint8_t version = ip[0] >> 4;
    if (version != 6) return false;

    const std::uint16_t payload_len = rd_be16(ip + 4);
    std::uint8_t next = ip[6];
    std::size_t off = kIpv6HdrLen;
    std::size_t end = kIpv6HdrLen + payload_len;
    if (end > remaining) end = remaining;

    // Walk extension headers (Hop-by-Hop, Routing, Destination, Fragment, AH).
    while (off < end) {
        if (next == kIpProtoUdp) break;
        std::size_t ext_len = 0;
        switch (next) {
            case 0:    // Hop-by-Hop
            case 43:   // Routing
            case 60:   // Destination Options
            case 135:  // Mobility
                if (off + 2 > end) return false;
                ext_len = (static_cast<std::size_t>(ip[off + 1]) + 1u) * 8u;
                next = ip[off];
                break;
            case 44:  // Fragment
                if (off + 8 > end) return false;
                // Skip non-first fragments.
                if ((rd_be16(ip + off + 2) & 0xFFF8u) != 0) return false;
                next = ip[off];
                ext_len = 8;
                break;
            case 51:  // Authentication Header
                if (off + 2 > end) return false;
                ext_len = (static_cast<std::size_t>(ip[off + 1]) + 2u) * 4u;
                next = ip[off];
                break;
            default:
                return false;  // unknown / no-next-header
        }
        if (ext_len == 0 || off + ext_len > end) return false;
        off += ext_len;
    }

    if (next != kIpProtoUdp) return false;
    return emit_udp(ip + off, end - off,
                    ipv6_to_string(ip + 8), ipv6_to_string(ip + 24),
                    hdr, cb);
}

bool dispatch_l3(std::uint16_t ethertype, const std::uint8_t* l3, std::size_t remaining,
                 const pcap_pkthdr* hdr, const PcapLoader::PayloadCallback& cb) {
    if (ethertype == kEthTypeIpv4) {
        return parse_ipv4(l3, remaining, hdr, cb);
    } else if (ethertype == kEthTypeIpv6) {
        return parse_ipv6(l3, remaining, hdr, cb);
    }
    return false;
}

// Strip Ethernet (and any VLAN tags), then dispatch to L3 parser.
bool parse_ethernet(const std::uint8_t* p, std::size_t len,
                    const pcap_pkthdr* hdr, const PcapLoader::PayloadCallback& cb) {
    if (len < 14) return false;
    std::size_t off = 12;
    std::uint16_t etype = rd_be16(p + off);
    off += 2;
    while ((etype == kEthTypeVlan || etype == kEthTypeQinQ) && off + 4 <= len) {
        etype = rd_be16(p + off + 2);
        off += 4;
    }
    if (off > len) return false;
    return dispatch_l3(etype, p + off, len - off, hdr, cb);
}

bool parse_linux_sll(const std::uint8_t* p, std::size_t len,
                     const pcap_pkthdr* hdr, const PcapLoader::PayloadCallback& cb) {
    constexpr std::size_t kSllLen = 16;
    if (len < kSllLen) return false;
    const std::uint16_t etype = rd_be16(p + 14);
    return dispatch_l3(etype, p + kSllLen, len - kSllLen, hdr, cb);
}

bool parse_null_loopback(const std::uint8_t* p, std::size_t len,
                         const pcap_pkthdr* hdr, const PcapLoader::PayloadCallback& cb) {
    if (len < 4) return false;
    // 4-byte host-order address family; common values: 2=IPv4, 24/28/30=IPv6.
    const std::uint32_t af = static_cast<std::uint32_t>(p[0]) |
                             (static_cast<std::uint32_t>(p[1]) << 8) |
                             (static_cast<std::uint32_t>(p[2]) << 16) |
                             (static_cast<std::uint32_t>(p[3]) << 24);
    if (af == 2) return parse_ipv4(p + 4, len - 4, hdr, cb);
    if (af == 24 || af == 28 || af == 30) return parse_ipv6(p + 4, len - 4, hdr, cb);
    return false;
}

}  // namespace

PcapLoader::~PcapLoader() { close(); }

bool PcapLoader::open(const std::string& path) {
    close();
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* h = pcap_open_offline(path.c_str(), errbuf);
    if (!h) {
        last_error_ = errbuf;
        return false;
    }
    handle_ = h;
    link_type_ = pcap_datalink(h);
    last_error_.clear();
    return true;
}

void PcapLoader::close() {
    if (handle_) {
        pcap_close(static_cast<pcap_t*>(handle_));
        handle_ = nullptr;
    }
    link_type_ = 0;
}

long PcapLoader::for_each_udp(const PayloadCallback& cb) {
    if (!handle_) {
        last_error_ = "pcap file is not open";
        return -1;
    }
    pcap_t* h = static_cast<pcap_t*>(handle_);
    long count = 0;
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* data = nullptr;
    while (true) {
        const int rc = pcap_next_ex(h, &hdr, &data);
        if (rc == 1) {
            const std::size_t len = hdr->caplen;
            bool ok = false;
            switch (link_type_) {
                case kDltEn10Mb:
                    ok = parse_ethernet(data, len, hdr, cb);
                    break;
                case kDltRaw:
                    if (len > 0 && (data[0] >> 4) == 6) {
                        ok = parse_ipv6(data, len, hdr, cb);
                    } else {
                        ok = parse_ipv4(data, len, hdr, cb);
                    }
                    break;
                case kDltLinuxSll:
                    ok = parse_linux_sll(data, len, hdr, cb);
                    break;
                case kDltNull:
                    ok = parse_null_loopback(data, len, hdr, cb);
                    break;
                default:
                    // Best effort: try Ethernet as a fallback for unknown link types.
                    ok = parse_ethernet(data, len, hdr, cb);
                    break;
            }
            if (ok) ++count;
        } else if (rc == 0) {
            // Live-capture timeout; not expected for offline files.
            continue;
        } else if (rc == PCAP_ERROR_BREAK) {
            break;
        } else if (rc == -2) {
            // End of savefile.
            break;
        } else {
            last_error_ = pcap_geterr(h);
            return -1;
        }
    }
    return count;
}

std::vector<UdpPayload> PcapLoader::load_all_udp() {
    std::vector<UdpPayload> out;
    for_each_udp([&](const UdpPayload& p) { out.push_back(p); });
    return out;
}

}  // namespace pcaproc
