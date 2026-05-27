#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "AsciiCharString.hpp"
#include "BigEndianInteger.hpp"

using tsembo::AsciiCharString;
using tsembo::BigEndianInteger;

TEST(AsciiCharString, DefaultIsEmpty) {
    AsciiCharString<8> s;
    EXPECT_EQ(s.size(), 8u);
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.length(), 0u);
    EXPECT_EQ(s.str(), "");
}

TEST(AsciiCharString, AssignFromCString) {
    AsciiCharString<8> s;
    s = "hello";
    EXPECT_EQ(s.length(), 5u);
    EXPECT_EQ(s.str(), "hello");
    EXPECT_EQ(s.data()[5], '\0');
    EXPECT_EQ(s.data()[6], '\0');
    EXPECT_EQ(s.data()[7], '\0');
}

TEST(AsciiCharString, TruncatesOverlongInput) {
    AsciiCharString<4> t;
    t = std::string("abcdef");
    EXPECT_EQ(t.length(), 4u);
    EXPECT_EQ(t.str(), "abcd");
}

TEST(AsciiCharString, TrimmedStripsTrailingSpaces) {
    AsciiCharString<8> q;
    std::memcpy(q.data(), "AB      ", 8);
    EXPECT_EQ(q.length(), 8u);
    EXPECT_EQ(q.str(), "AB      ");
    EXPECT_EQ(q.trimmed(), "AB");
}

TEST(AsciiCharString, Equality) {
    AsciiCharString<4> a("abcd");
    AsciiCharString<4> b("abcd");
    AsciiCharString<4> c("abce");
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(AsciiCharString, OverlayLoginMessage) {
    struct LoginMessage {
        AsciiCharString<8>  username;
        AsciiCharString<16> password;
        BigEndianInteger<std::uint32_t> session_id;
    };
    static_assert(sizeof(LoginMessage) == 8 + 16 + 4, "wire layout must be packed");

    unsigned char wire[28] = {0};
    std::memcpy(wire + 0, "alice\0\0\0", 8);
    std::memcpy(wire + 8, "secret          ", 16);
    wire[24] = 0x00;
    wire[25] = 0x00;
    wire[26] = 0x10;
    wire[27] = 0x2A;

    LoginMessage msg;
    std::memcpy(&msg, wire, sizeof(msg));
    EXPECT_EQ(msg.username.str(), "alice");
    EXPECT_EQ(msg.password.trimmed(), "secret");
    EXPECT_EQ(msg.session_id.value(), 0x0000102Au);
}
