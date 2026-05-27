#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pcaproc {

// Represents the UDP payload of a single packet extracted from a pcap file.
struct UdpPayload {
    // Capture timestamp (seconds and microseconds since epoch, as stored in the pcap record).
    std::uint64_t ts_sec = 0;
    std::uint32_t ts_usec = 0;

    // Network-layer addresses in presentation form (e.g. "10.0.0.1", "fe80::1").
    std::string src_ip;
    std::string dst_ip;

    // Transport-layer ports in host byte order.
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;

    // Raw UDP payload bytes (without the UDP header).
    std::vector<std::uint8_t> data;
};

// Loads a pcap file and yields the payload of every UDP packet it contains.
//
// Supports the link-layer types most commonly found in pcap captures:
//   - Ethernet (DLT_EN10MB), including 802.1Q VLAN tags
//   - Raw IP   (DLT_RAW)
//   - Linux cooked capture v1 (DLT_LINUX_SLL)
//   - Null/Loopback (DLT_NULL)
//
// Both IPv4 and IPv6 are decoded. IPv4 fragments other than the first are skipped.
class PcapLoader {
public:
    using PayloadCallback = std::function<void(const UdpPayload&)>;

    PcapLoader() = default;

    // Open the given pcap file. Returns false on failure; call last_error() for details.
    bool open(const std::string& path);

    // Close the underlying handle (also called automatically by the destructor).
    void close();

    ~PcapLoader();

    PcapLoader(const PcapLoader&) = delete;
    PcapLoader& operator=(const PcapLoader&) = delete;

    // Iterate the file and invoke `cb` for each UDP packet found.
    // Returns the number of UDP payloads delivered, or a negative value on error.
    long for_each_udp(const PayloadCallback& cb);

    // Convenience: load all UDP payloads into a vector.
    std::vector<UdpPayload> load_all_udp();

    const std::string& last_error() const { return last_error_; }

private:
    void* handle_ = nullptr;  // pcap_t*
    int link_type_ = 0;
    std::string last_error_;
};

}  // namespace pcaproc
