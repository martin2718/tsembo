#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "IndicativeVolumeBook.hpp"
#include "MessageParser.hpp"
#include "Messages.hpp"

using tsembo::ATagAddOrder;
using tsembo::CTagOrderExecutedWithPrice;
using tsembo::DTagOrderDelete;
using tsembo::ETagOrderExecuted;
using tsembo::IndicativeVolumeBook;
using tsembo::MessageParser;
using tsembo::PacketHeader;
using tsembo::RTagReset;
using tsembo::TagView;

namespace {

// Wrap a packed tag-body struct into a TagView, with a small holder for the
// length byte + body so the pointers stay valid for the test's scope.
template <class Body>
struct TaggedRecord {
    std::vector<std::uint8_t> bytes;  // [length][body...]
    TagView view() const {
        TagView v;
        v.raw       = bytes.data();
        v.raw_size  = bytes.size();
        v.tag       = bytes[1];                 // message type byte
        v.body      = bytes.data() + 2;
        v.body_size = bytes.size() - 2;
        return v;
    }
};

template <class Body>
TaggedRecord<Body> wrap(const Body& body) {
    TaggedRecord<Body> rec;
    rec.bytes.resize(1 + sizeof(Body));
    rec.bytes[0] = static_cast<std::uint8_t>(sizeof(Body));
    std::memcpy(rec.bytes.data() + 1, &body, sizeof(Body));
    return rec;
}

ATagAddOrder make_add(std::uint32_t order_id, char side,
                      std::uint64_t qty, std::uint64_t price) {
    ATagAddOrder a{};
    a.messageType = std::uint8_t{'A'};
    a.timeMicroseconds = std::uint32_t{0};
    a.orderId = order_id;
    a.side[0] = side;
    // 6-byte big-endian quantity (max 2^48-1)
    for (int i = 0; i < 6; ++i) {
        a.quantity.bytes[5 - i] = static_cast<unsigned char>((qty >> (8 * i)) & 0xFFu);
    }
    a.price = price;
    a.orderCondition = std::uint8_t{0};
    a.modificationFlag = std::uint8_t{0};
    return a;
}

DTagOrderDelete make_del(std::uint32_t order_id, char side) {
    DTagOrderDelete d{};
    d.messageType = std::uint8_t{'D'};
    d.timeMicroseconds = std::uint32_t{0};
    d.orderId = order_id;
    d.side[0] = side;
    d.modificationFlag = std::uint8_t{0};
    return d;
}

ETagOrderExecuted make_exec(std::uint32_t order_id, char side, std::uint64_t vol) {
    ETagOrderExecuted e{};
    e.messageType = std::uint8_t{'E'};
    e.timeMicroseconds = std::uint32_t{0};
    e.orderId = order_id;
    e.side[0] = side;
    for (int i = 0; i < 6; ++i) {
        e.volume.bytes[5 - i] = static_cast<unsigned char>((vol >> (8 * i)) & 0xFFu);
    }
    e.matchId = std::uint32_t{0};
    return e;
}

CTagOrderExecutedWithPrice make_cexec(std::uint32_t order_id, char side,
                                      std::uint64_t vol, std::uint64_t price) {
    CTagOrderExecutedWithPrice c{};
    c.messageType = std::uint8_t{'C'};
    c.timeMicroseconds = std::uint32_t{0};
    c.orderId = order_id;
    c.side[0] = side;
    for (int i = 0; i < 6; ++i) {
        c.volume.bytes[5 - i] = static_cast<unsigned char>((vol >> (8 * i)) & 0xFFu);
    }
    c.matchId = std::uint32_t{0};
    c.executionPrice = price;
    c.adoptedPricingMethod = std::uint8_t{1};
    return c;
}

}  // namespace

TEST(IndicativeVolumeBook, EmptyBookHasZeroVolume) {
    IndicativeVolumeBook book;
    EXPECT_EQ(book.indicative_volume_at(1000), 0u);
    EXPECT_EQ(book.bid_levels(), 0u);
    EXPECT_EQ(book.ask_levels(), 0u);
}

TEST(IndicativeVolumeBook, AddOrdersBuildAggregateAndCross) {
    IndicativeVolumeBook book;
    // Bids: 100@1010, 200@1000, 50@990
    // Asks: 80@1020, 150@1010, 60@1030
    auto b1 = wrap(make_add(1, 'B', 100, 1010));
    auto b2 = wrap(make_add(2, 'B', 200, 1000));
    auto b3 = wrap(make_add(3, 'B',  50,  990));
    auto a1 = wrap(make_add(4, 'S',  80, 1020));
    auto a2 = wrap(make_add(5, 'S', 150, 1010));
    auto a3 = wrap(make_add(6, 'S',  60, 1030));

    for (auto* r : {&b1, &b2, &b3, &a1, &a2, &a3}) {
        EXPECT_TRUE(book.apply(r->view()));
    }
    EXPECT_EQ(book.bid_levels(), 3u);
    EXPECT_EQ(book.ask_levels(), 3u);
    EXPECT_EQ(book.order_count(), 6u);

    // At P=1010: buys >=1010 = 100; sells <=1010 = 150 -> cross = 100
    EXPECT_EQ(book.buy_quantity_at_or_above(1010), 100u);
    EXPECT_EQ(book.sell_quantity_at_or_below(1010), 150u);
    EXPECT_EQ(book.indicative_volume_at(1010), 100u);

    // At P=1020: buys >=1020 = 0; sells <=1020 = 230 -> cross = 0
    EXPECT_EQ(book.indicative_volume_at(1020), 0u);

    // At P=1000: buys >=1000 = 300; sells <=1000 = 0 -> cross = 0
    EXPECT_EQ(book.indicative_volume_at(1000), 0u);
}

TEST(IndicativeVolumeBook, MarketOrdersAreAlwaysCrossable) {
    IndicativeVolumeBook book;
    const auto kMkt = IndicativeVolumeBook::kMarketOrder;

    auto mb = wrap(make_add(1, 'B', 500, kMkt));
    auto a1 = wrap(make_add(2, 'S', 200, 1010));
    auto a2 = wrap(make_add(3, 'S', 100,  990));
    for (auto* r : {&mb, &a1, &a2}) EXPECT_TRUE(book.apply(r->view()));

    // Market bids count at any price.
    EXPECT_EQ(book.buy_quantity_at_or_above(1010), 500u);
    EXPECT_EQ(book.sell_quantity_at_or_below(1010), 300u);
    EXPECT_EQ(book.indicative_volume_at(1010), 300u);

    // No limit bid >= 990, but market bid still crosses.
    EXPECT_EQ(book.indicative_volume_at(990), 100u);
}

TEST(IndicativeVolumeBook, DeleteAndExecutionReduceBook) {
    IndicativeVolumeBook book;
    auto b1 = wrap(make_add(1, 'B', 100, 1000));
    auto b2 = wrap(make_add(2, 'B', 200, 1000));
    auto s1 = wrap(make_add(3, 'S', 150, 1000));
    for (auto* r : {&b1, &b2, &s1}) EXPECT_TRUE(book.apply(r->view()));

    EXPECT_EQ(book.indicative_volume_at(1000), 150u);

    // Partial Zaraba execution against order 1: 40 shares.
    auto e = wrap(make_exec(1, 'B', 40));
    EXPECT_TRUE(book.apply(e.view()));
    // Bids at 1000: now 60 + 200 = 260; sells unchanged 150; cross = 150.
    EXPECT_EQ(book.indicative_volume_at(1000), 150u);

    // Cancel order 2 entirely.
    auto d = wrap(make_del(2, 'B'));
    EXPECT_TRUE(book.apply(d.view()));
    // Bids at 1000: 60 only; sells 150; cross = 60.
    EXPECT_EQ(book.indicative_volume_at(1000), 60u);
    EXPECT_EQ(book.order_count(), 2u);  // order 1 (60 left) + order 3
}

TEST(IndicativeVolumeBook, CTagItayoseExecutionReducesBook) {
    IndicativeVolumeBook book;
    auto b1 = wrap(make_add(10, 'B', 300, 1000));
    auto s1 = wrap(make_add(11, 'S', 300, 1000));
    book.apply(b1.view());
    book.apply(s1.view());
    EXPECT_EQ(book.indicative_volume_at(1000), 300u);

    auto c_buy  = wrap(make_cexec(10, 'B', 300, 1000));
    auto c_sell = wrap(make_cexec(11, 'S', 300, 1000));
    EXPECT_TRUE(book.apply(c_buy.view()));
    EXPECT_TRUE(book.apply(c_sell.view()));
    EXPECT_EQ(book.indicative_volume_at(1000), 0u);
    EXPECT_EQ(book.order_count(), 0u);
}

TEST(IndicativeVolumeBook, ResetClearsBookOnStartFlag) {
    IndicativeVolumeBook book;
    auto b1 = wrap(make_add(1, 'B', 100, 1000));
    auto s1 = wrap(make_add(2, 'S', 100, 1000));
    book.apply(b1.view());
    book.apply(s1.view());
    EXPECT_GT(book.order_count(), 0u);

    RTagReset r{};
    r.messageType = std::uint8_t{'R'};
    r.startEndFlag = std::uint8_t{1};
    auto rec = wrap(r);
    EXPECT_TRUE(book.apply(rec.view()));
    EXPECT_EQ(book.order_count(), 0u);
    EXPECT_EQ(book.bid_levels(), 0u);
    EXPECT_EQ(book.ask_levels(), 0u);

    // End-flag reset (==2) is ignored.
    r.startEndFlag = std::uint8_t{2};
    auto rec2 = wrap(r);
    EXPECT_FALSE(book.apply(rec2.view()));
}

TEST(IndicativeVolumeBook, AddTagUpsertsOnSameOrderId) {
    // The spec models quantity-reduction modifications as a re-issued A tag
    // for the same orderId; the latest A carries the current resting size.
    IndicativeVolumeBook book;
    auto a1 = wrap(make_add(7, 'B', 500, 1000));
    auto a2 = wrap(make_add(7, 'B', 200, 1000));  // reduced
    book.apply(a1.view());
    book.apply(a2.view());
    EXPECT_EQ(book.order_count(), 1u);
    EXPECT_EQ(book.buy_quantity_at_or_above(1000), 200u);
}

TEST(IndicativeVolumeBook, IgnoresUnrelatedAndMalformedTags) {
    IndicativeVolumeBook book;

    // Unrelated tag type: 'T' (Seconds Timestamp).
    std::vector<std::uint8_t> t_bytes{0x05, 'T', 0, 0, 0, 0};
    TagView t{};
    t.raw = t_bytes.data(); t.raw_size = t_bytes.size();
    t.tag = 'T'; t.body = t_bytes.data() + 2; t.body_size = 4;
    EXPECT_FALSE(book.apply(t));

    // 'A' tag with wrong body size: 5 instead of 26.
    std::vector<std::uint8_t> bad{0x05, 'A', 0, 0, 0, 0};
    TagView bv{};
    bv.raw = bad.data(); bv.raw_size = bad.size();
    bv.tag = 'A'; bv.body = bad.data() + 2; bv.body_size = 4;
    EXPECT_FALSE(book.apply(bv));
}

TEST(IndicativeVolumeBook, IntegratesWithMessageParser) {
    // Build a payload with PacketHeader + two A tags and feed it through
    // MessageParser via the apply_payload helper.
    std::vector<std::uint8_t> buf(sizeof(PacketHeader), 0);
    PacketHeader hdr{};
    hdr.messageCount = std::uint8_t{2};
    std::memcpy(buf.data(), &hdr, sizeof(hdr));

    auto a1 = wrap(make_add(1, 'B', 100, 1000));
    auto a2 = wrap(make_add(2, 'S', 100, 1000));
    buf.insert(buf.end(), a1.bytes.begin(), a1.bytes.end());
    buf.insert(buf.end(), a2.bytes.begin(), a2.bytes.end());

    IndicativeVolumeBook book;
    MessageParser parser;
    std::size_t applied = book.apply_payload(parser, buf.data(), buf.size());
    EXPECT_EQ(applied, 2u);
    EXPECT_EQ(book.indicative_volume_at(1000), 100u);
}
