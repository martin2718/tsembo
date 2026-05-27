#include "MessageParser.hpp"

#include <cstring>

namespace tsembo {

ParseResult MessageParser::parse(const std::uint8_t* data, std::size_t size,
                                 const TagCallback& cb) const {
    ParseResult result;

    if (data == nullptr || size < sizeof(PacketHeader)) {
        result.status = ParseStatus::TooShortForHeader;
        return result;
    }

    // Overlay the on-wire header. PacketHeader is packed and trivially
    // copyable, so this is well-defined for the lifetime of `data`.
    const auto* header = reinterpret_cast<const PacketHeader*>(data);
    result.bytes_consumed = sizeof(PacketHeader);

    const std::size_t expected_tags = static_cast<std::size_t>(header->messageCount.value());

    std::size_t off = sizeof(PacketHeader);
    while (off < size) {
        const std::uint8_t length = data[off];
        if (length < 1) {
            // Length must cover at least the Message Type byte.
            result.status = ParseStatus::InvalidLength;
            return result;
        }
        const std::size_t record_size = static_cast<std::size_t>(length) + 1u;
        if (off + record_size > size) {
            result.status = ParseStatus::TruncatedSubmessage;
            return result;
        }

        TagView view;
        view.raw       = data + off;
        view.raw_size  = record_size;
        view.tag       = data[off + 1];
        view.body      = data + off + 2;
        view.body_size = static_cast<std::size_t>(length) - 1u;

        if (cb) {
            cb(*header, view);
        }

        result.tags_parsed += 1;
        off += record_size;
        result.bytes_consumed = off;
    }

    if (result.tags_parsed != expected_tags) {
        result.status = ParseStatus::MessageCountMismatch;
        return result;
    }

    result.status = ParseStatus::Ok;
    return result;
}

ParseResult MessageParser::parse(const UdpPayload& payload, const TagCallback& cb) const {
    return parse(payload.data.data(), payload.data.size(), cb);
}

}  // namespace tsembo
