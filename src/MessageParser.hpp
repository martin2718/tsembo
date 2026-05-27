#pragma once

#include "Messages.hpp"
#include "PcapLoader.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>

namespace pcaproc {

// View of a single submessage (tag) inside a packet payload.
//
// Wire layout per the TSE arrowhead FLEX MBO spec (sec. 3.1.1):
//
//     +--------+----------+-------------------------+
//     | Length | Msg Type | Payload (Length-1 bytes)|
//     | 1 byte | 1 byte   |                         |
//     +--------+----------+-------------------------+
//
// The `Length` byte encodes the size of the tag data that follows it (i.e.
// Message Type byte plus payload). The next submessage starts at
// `raw + 1 + length`. The Message Type byte is an ASCII character such as
// 'T', 'O', 'K', 'A', 'E', 'C', 'D', 'R', 'L'.
//
// `body` points into the original payload buffer. The view is only valid
// for the lifetime of that buffer (typically the scope of the callback).
struct TagView {
    std::uint8_t        tag        = 0;        // Message Type byte (e.g. 'T')
    const std::uint8_t* body       = nullptr;  // bytes after the message type
    std::size_t         body_size  = 0;        // == length - 1
    const std::uint8_t* raw        = nullptr;  // start of the length byte
    std::size_t         raw_size   = 0;        // == 1 + length
};

// Outcome of parsing a single payload.
enum class ParseStatus {
    Ok,                     // Whole payload consumed; tags_parsed == header.messageCount.
    TooShortForHeader,      // Buffer smaller than sizeof(PacketHeader).
    TruncatedSubmessage,    // A submessage's declared length runs past end of buffer.
    InvalidLength,          // A submessage declared length == 0 (no Message Type byte).
    MessageCountMismatch,   // Tag count in payload disagrees with header.messageCount.
};

struct ParseResult {
    ParseStatus  status         = ParseStatus::Ok;
    std::size_t  tags_parsed    = 0;  // number of submessages successfully delivered
    std::size_t  bytes_consumed = 0;  // bytes read from the payload, header included
};

// Parses payloads emitted by `PcapLoader`. Each payload begins with a
// `PacketHeader` and is followed by `PacketHeader::messageCount` submessages
// (tags). The parser is stateless; one instance can be reused across packets.
//
// Usage:
//
//     pcaproc::MessageParser parser;
//     loader.for_each_udp([&](const pcaproc::UdpPayload& pkt) {
//         parser.parse(pkt, [&](const pcaproc::PacketHeader& hdr,
//                               const pcaproc::TagView& tag) {
//             // dispatch on tag.tag, read tag.body / tag.body_size
//         });
//     });
class MessageParser {
public:
    using TagCallback = std::function<void(const PacketHeader&, const TagView&)>;

    MessageParser() = default;

    // Parse a single payload. `data`/`size` must point to the full UDP
    // payload (i.e. starting at the PacketHeader). The callback is invoked
    // for every well-formed submessage encountered; on a malformed record
    // the parser stops and returns the corresponding status.
    ParseResult parse(const std::uint8_t* data, std::size_t size,
                      const TagCallback& cb) const;

    // Convenience overload that operates on a `UdpPayload`.
    ParseResult parse(const UdpPayload& payload, const TagCallback& cb) const;
};

}  // namespace pcaproc
