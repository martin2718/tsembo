#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "MessageParser.hpp"
#include "Messages.hpp"

using tsembo::ATagAddOrder;
using tsembo::MessageParser;
using tsembo::PacketHeader;
using tsembo::ParseStatus;
using tsembo::RTagReset;
using tsembo::TagView;
using tsembo::TTagSecondsTimestamp;
namespace TagType = tsembo::TagType;

namespace {

// Build a payload: PacketHeader (with messageCount) followed by raw tag bytes.
std::vector<std::uint8_t> make_payload(std::uint8_t message_count,
                                       const std::vector<std::uint8_t>& tag_bytes) {
    std::vector<std::uint8_t> buf(sizeof(PacketHeader), 0);
    PacketHeader hdr{};
    hdr.multicastGroupNumber = std::uint8_t{1};
    hdr.numberOfSystemReboots = std::uint8_t{2};
    hdr.sequenceNumber = std::uint32_t{0x01020304};
    hdr.issueCode = "TEST00000000";
    hdr.updateNumber = std::uint32_t{42};
    hdr.packetNumber = std::uint8_t{1};
    hdr.totalNumberOfPackets = std::uint8_t{1};
    hdr.utilityFlag = std::uint8_t{0};
    hdr.messageCount = message_count;
    std::memcpy(buf.data(), &hdr, sizeof(hdr));
    buf.insert(buf.end(), tag_bytes.begin(), tag_bytes.end());
    return buf;
}

}  // namespace

TEST(MessageParser, EmptyPayloadIsHeaderOnlyWithZeroTags) {
    auto buf = make_payload(/*message_count=*/0, /*tags=*/{});
    MessageParser parser;
    std::size_t calls = 0;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader&, const TagView&) { ++calls; });
    EXPECT_EQ(r.status, ParseStatus::Ok);
    EXPECT_EQ(r.tags_parsed, 0u);
    EXPECT_EQ(calls, 0u);
    EXPECT_EQ(r.bytes_consumed, sizeof(PacketHeader));
}

TEST(MessageParser, ParsesSingleTag) {
    // Length=4 (body bytes that follow), MsgType='X', payload = {0xAA, 0xBB, 0xCC}
    std::vector<std::uint8_t> tags{0x04, 'X', 0xAA, 0xBB, 0xCC};
    auto buf = make_payload(1, tags);

    MessageParser parser;
    std::vector<TagView> seen;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader& hdr, const TagView& v) {
                              EXPECT_EQ(hdr.messageCount.value(), 1);
                              seen.push_back(v);
                          });

    EXPECT_EQ(r.status, ParseStatus::Ok);
    EXPECT_EQ(r.tags_parsed, 1u);
    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen[0].tag, static_cast<std::uint8_t>('X'));
    EXPECT_EQ(seen[0].raw_size, 5u);     // length byte + 4 body bytes
    ASSERT_EQ(seen[0].body_size, 3u);    // payload after the message type byte
    EXPECT_EQ(seen[0].body[0], 0xAA);
    EXPECT_EQ(seen[0].body[1], 0xBB);
    EXPECT_EQ(seen[0].body[2], 0xCC);
}

TEST(MessageParser, ParsesMultipleTagsInOrder) {
    std::vector<std::uint8_t> tags{
        0x02, 'A', 0x01,                   // 'A' tag, payload {0x01}
        0x03, 'B', 0x02, 0x03,             // 'B' tag, payload {0x02,0x03}
        0x01, 'C',                         // 'C' tag, empty payload
    };
    auto buf = make_payload(3, tags);

    MessageParser parser;
    std::vector<std::uint8_t> tag_ids;
    std::vector<std::size_t> body_sizes;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader&, const TagView& v) {
                              tag_ids.push_back(v.tag);
                              body_sizes.push_back(v.body_size);
                          });

    EXPECT_EQ(r.status, ParseStatus::Ok);
    EXPECT_EQ(r.tags_parsed, 3u);
    EXPECT_EQ(r.bytes_consumed, buf.size());
    EXPECT_EQ(tag_ids, (std::vector<std::uint8_t>{'A', 'B', 'C'}));
    EXPECT_EQ(body_sizes, (std::vector<std::size_t>{1u, 2u, 0u}));
}

TEST(MessageParser, RejectsPayloadShorterThanHeader) {
    std::vector<std::uint8_t> tiny(sizeof(PacketHeader) - 1, 0);
    MessageParser parser;
    auto r = parser.parse(tiny.data(), tiny.size(),
                          [](const PacketHeader&, const TagView&) {});
    EXPECT_EQ(r.status, ParseStatus::TooShortForHeader);
    EXPECT_EQ(r.tags_parsed, 0u);
}

TEST(MessageParser, RejectsInvalidLengthByte) {
    // Length=0 means no Message Type byte -- invalid.
    std::vector<std::uint8_t> tags{0x00};
    auto buf = make_payload(1, tags);
    MessageParser parser;
    std::size_t calls = 0;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader&, const TagView&) { ++calls; });
    EXPECT_EQ(r.status, ParseStatus::InvalidLength);
    EXPECT_EQ(calls, 0u);
}

TEST(MessageParser, RejectsTruncatedSubmessage) {
    // Declared length=10 but only 2 bytes of body follow.
    std::vector<std::uint8_t> tags{0x0A, 'A', 0x00};
    auto buf = make_payload(1, tags);
    MessageParser parser;
    auto r = parser.parse(buf.data(), buf.size(),
                          [](const PacketHeader&, const TagView&) {});
    EXPECT_EQ(r.status, ParseStatus::TruncatedSubmessage);
    EXPECT_EQ(r.tags_parsed, 0u);
}

TEST(MessageParser, DetectsMessageCountMismatch) {
    // Two tags on the wire but header says 5.
    std::vector<std::uint8_t> tags{
        0x01, 'R',
        0x01, 'R',
    };
    auto buf = make_payload(5, tags);
    MessageParser parser;
    std::size_t calls = 0;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader&, const TagView&) { ++calls; });
    EXPECT_EQ(r.status, ParseStatus::MessageCountMismatch);
    EXPECT_EQ(r.tags_parsed, 2u);
    EXPECT_EQ(calls, 2u);
}

// --- Concrete FLEX MBO tag structs ------------------------------------------

TEST(FlexTags, FixedSizes) {
    // Lengths from arrowhead FLEX MBO spec v0.6 sec. 3.2.2.
    static_assert(sizeof(tsembo::TTagSecondsTimestamp)       == 5,  "");
    static_assert(sizeof(tsembo::OTagTradingStatus)          == 18, "");
    static_assert(sizeof(tsembo::KTagExecutionSummary)       == 46, "");
    static_assert(sizeof(tsembo::ATagAddOrder)               == 26, "");
    static_assert(sizeof(tsembo::ETagOrderExecuted)          == 20, "");
    static_assert(sizeof(tsembo::CTagOrderExecutedWithPrice) == 29, "");
    static_assert(sizeof(tsembo::DTagOrderDelete)            == 11, "");
    static_assert(sizeof(tsembo::RTagReset)                  == 2,  "");
    static_assert(sizeof(tsembo::LTagControl)                == 3,  "");
    SUCCEED();
}

TEST(FlexTags, ParseTTagFromPayload) {
    // T tag: length=5, body = 'T' + 4-byte BE seconds (0x65 8E 73 1E = 1703782174)
    std::vector<std::uint8_t> tags{0x05, 'T', 0x65, 0x8E, 0x73, 0x1E};
    auto buf = make_payload(1, tags);

    MessageParser parser;
    bool saw_t = false;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader&, const TagView& v) {
                              if (v.tag == TagType::SecondsTimestamp) {
                                  ASSERT_EQ(v.raw_size, sizeof(TTagSecondsTimestamp) + 1);
                                  const auto* t = reinterpret_cast<const TTagSecondsTimestamp*>(v.raw + 1);
                                  EXPECT_EQ(t->messageType.value(), static_cast<std::uint8_t>('T'));
                                  EXPECT_EQ(t->timeSeconds.value(), 0x658E731Eu);
                                  saw_t = true;
                              }
                          });
    EXPECT_EQ(r.status, ParseStatus::Ok);
    EXPECT_TRUE(saw_t);
}

TEST(FlexTags, ParseATagWith48BitQuantity) {
    // A tag length=26, body laid out per spec.
    // time=0x00010203, orderId=0x04050607, side='S',
    // quantity (6 BE bytes) = 0x000000002710 = 10000,
    // price = 0x0000000000100000 = 1048576,
    // orderCondition=0, modificationFlag=1
    std::vector<std::uint8_t> body{
        'A',
        0x00, 0x01, 0x02, 0x03,             // time
        0x04, 0x05, 0x06, 0x07,             // order id
        'S',                                // side
        0x00, 0x00, 0x00, 0x00, 0x27, 0x10, // quantity (6 bytes BE) = 10000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,  // price = 0x100000
        0x00,                               // order condition
        0x01,                               // modification flag
    };
    ASSERT_EQ(body.size(), 26u);

    std::vector<std::uint8_t> tags;
    tags.push_back(static_cast<std::uint8_t>(body.size()));  // length byte
    tags.insert(tags.end(), body.begin(), body.end());
    auto buf = make_payload(1, tags);

    MessageParser parser;
    bool saw = false;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader&, const TagView& v) {
                              ASSERT_EQ(v.tag, static_cast<std::uint8_t>('A'));
                              const auto* a = reinterpret_cast<const ATagAddOrder*>(v.raw + 1);
                              EXPECT_EQ(a->timeMicroseconds.value(), 0x00010203u);
                              EXPECT_EQ(a->orderId.value(), 0x04050607u);
                              EXPECT_EQ(a->side[0], 'S');
                              EXPECT_EQ(a->quantity.value(), 10000u);
                              EXPECT_EQ(a->price.value(), 0x100000u);
                              EXPECT_EQ(a->orderCondition.value(), 0u);
                              EXPECT_EQ(a->modificationFlag.value(), 1u);
                              saw = true;
                          });
    EXPECT_EQ(r.status, ParseStatus::Ok);
    EXPECT_TRUE(saw);
}

TEST(FlexTags, ParseRTagReset) {
    // R tag length=2: 'R' + startEndFlag
    std::vector<std::uint8_t> tags{0x02, 'R', 0x01};
    auto buf = make_payload(1, tags);
    MessageParser parser;
    bool saw = false;
    auto r = parser.parse(buf.data(), buf.size(),
                          [&](const PacketHeader&, const TagView& v) {
                              ASSERT_EQ(v.tag, static_cast<std::uint8_t>('R'));
                              const auto* rt = reinterpret_cast<const RTagReset*>(v.raw + 1);
                              EXPECT_EQ(rt->startEndFlag.value(), 1u);
                              saw = true;
                          });
    EXPECT_EQ(r.status, ParseStatus::Ok);
    EXPECT_TRUE(saw);
}
