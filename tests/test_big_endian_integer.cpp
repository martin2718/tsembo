#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "BigEndianInteger.hpp"

using pcaproc::BigEndianInteger;

TEST(BigEndianInteger, Layout) {
    static_assert(sizeof(BigEndianInteger<std::uint16_t>) == 2, "");
    static_assert(sizeof(BigEndianInteger<std::uint32_t>) == 4, "");
    static_assert(sizeof(BigEndianInteger<std::uint64_t>) == 8, "");
    SUCCEED();
}

TEST(BigEndianInteger, Uint16Roundtrip) {
    BigEndianInteger<std::uint16_t> u16;
    u16.set(0x1234);
    EXPECT_EQ(u16.data()[0], 0x12);
    EXPECT_EQ(u16.data()[1], 0x34);
    EXPECT_EQ(u16.value(), 0x1234);
    EXPECT_EQ(static_cast<std::uint16_t>(u16), 0x1234);
}

TEST(BigEndianInteger, Uint32Roundtrip) {
    BigEndianInteger<std::uint32_t> u32(0xDEADBEEFu);
    EXPECT_EQ(u32.data()[0], 0xDE);
    EXPECT_EQ(u32.data()[1], 0xAD);
    EXPECT_EQ(u32.data()[2], 0xBE);
    EXPECT_EQ(u32.data()[3], 0xEF);
    EXPECT_EQ(u32.value(), 0xDEADBEEFu);
}

TEST(BigEndianInteger, Uint64Roundtrip) {
    BigEndianInteger<std::uint64_t> u64;
    u64 = 0x0102030405060708ull;
    for (int i = 0; i < 8; ++i) {
        EXPECT_EQ(u64.data()[i], static_cast<unsigned char>(i + 1));
    }
    EXPECT_EQ(u64.value(), 0x0102030405060708ull);
}

TEST(BigEndianInteger, SignedNegatives) {
    BigEndianInteger<std::int16_t> s16(-1);
    EXPECT_EQ(s16.data()[0], 0xFF);
    EXPECT_EQ(s16.data()[1], 0xFF);
    EXPECT_EQ(s16.value(), -1);

    BigEndianInteger<std::int32_t> s32(-2);
    EXPECT_EQ(s32.data()[0], 0xFF);
    EXPECT_EQ(s32.data()[3], 0xFE);
    EXPECT_EQ(s32.value(), -2);
}

TEST(BigEndianInteger, OverlayUdpHeader) {
    struct UdpHeader {
        BigEndianInteger<std::uint16_t> src_port;
        BigEndianInteger<std::uint16_t> dst_port;
        BigEndianInteger<std::uint16_t> length;
        BigEndianInteger<std::uint16_t> checksum;
    };
    static_assert(sizeof(UdpHeader) == 8, "wire layout must be 8 bytes");

    const unsigned char wire[8] = {
        0x00, 0x35,
        0xC0, 0x00,
        0x00, 0x20,
        0xAB, 0xCD,
    };
    UdpHeader hdr;
    std::memcpy(&hdr, wire, sizeof(hdr));
    EXPECT_EQ(hdr.src_port.value(), 53);
    EXPECT_EQ(hdr.dst_port.value(), 49152);
    EXPECT_EQ(hdr.length.value(), 32);
    EXPECT_EQ(hdr.checksum.value(), 0xABCD);
}
