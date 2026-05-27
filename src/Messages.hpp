#pragma once

#include "AsciiCharString.hpp"
#include "BigEndianInteger.hpp"

#include <cstdint>
#include <cstddef>

// Force 1-byte alignment for every aggregate declared between
// PCAPROC_PACK_BEGIN and PCAPROC_PACK_END so on-wire message layouts
// have no implicit padding. Works on GCC/Clang and MSVC.
#if defined(_MSC_VER)
    #define PCAPROC_PACK_BEGIN __pragma(pack(push, 1))
    #define PCAPROC_PACK_END   __pragma(pack(pop))
    #define PCAPROC_PACKED
#elif defined(__GNUC__) || defined(__clang__)
    #define PCAPROC_PACK_BEGIN _Pragma("pack(push, 1)")
    #define PCAPROC_PACK_END   _Pragma("pack(pop)")
    #define PCAPROC_PACKED     __attribute__((packed))
#else
    #define PCAPROC_PACK_BEGIN
    #define PCAPROC_PACK_END
    #define PCAPROC_PACKED
#endif

namespace tsembo {

PCAPROC_PACK_BEGIN

struct PacketHeader {
    // PUBLIC DATA
    BigEndianUInt8        multicastGroupNumber;
    BigEndianUInt8        numberOfSystemReboots;
    BigEndianUInt32       sequenceNumber;
    AsciiCharString<12>   issueCode;
    BigEndianUInt32       updateNumber;
    BigEndianUInt8        packetNumber;
    BigEndianUInt8        totalNumberOfPackets;
    BigEndianUInt8        utilityFlag;
    BigEndianUInt8        messageCount;
};
static_assert(sizeof(PacketHeader) == 26);

// -----------------------------------------------------------------------------
// Tag bodies for the TSE arrowhead FLEX Market-by-Order service.
//
// On-wire layout of each submessage:
//
//     [Length:1][MessageType:1][Body:Length-1]
//
// The structs below model the MessageType byte plus the body fields, i.e.
// they are sized exactly to `Length`. Overlay them onto `TagView::raw + 1`
// (which is `TagView::body - 1`) after verifying both the message type and
// `1 + body_size == sizeof(TagBody)`.
//
// All multi-byte integers are big-endian on the wire; price fields use
// `BigEndianUInt64` with the last four digits being decimal fractions
// (e.g. wire value 1050000 == price 105.0000).
//
// Source: arrowhead FLEX MBO Specifications v0.6, sec. 3.2.3.
// -----------------------------------------------------------------------------

// Message Type byte values (the leading byte of every tag body).
namespace TagType {
    constexpr std::uint8_t SecondsTimestamp        = 'T';
    constexpr std::uint8_t TradingStatus           = 'O';
    constexpr std::uint8_t ExecutionSummary        = 'K';
    constexpr std::uint8_t AddOrder                = 'A';
    constexpr std::uint8_t OrderExecuted           = 'E';
    constexpr std::uint8_t OrderExecutedWithPrice  = 'C';
    constexpr std::uint8_t OrderDelete             = 'D';
    constexpr std::uint8_t Reset                   = 'R';
    constexpr std::uint8_t Control                 = 'L';
}  // namespace TagType

// (1) Seconds Timestamp -- T tag (5 bytes)
struct TTagSecondsTimestamp {
    BigEndianUInt8   messageType;     // 'T'
    BigEndianUInt32  timeSeconds;     // UNIX time (seconds)
};
static_assert(sizeof(TTagSecondsTimestamp) == 5);

// (2) Trading Status -- O tag (18 bytes)
struct OTagTradingStatus {
    BigEndianUInt8       messageType;       // 'O'
    BigEndianUInt32      timeMicroseconds;
    BigEndianUInt8       marketStatus;
    AsciiCharString<2>   statusFlag;        // e.g. "A0", "B1", or two spaces
    BigEndianUInt8       shortSellingStatus;
    BigEndianUInt8       pricingMethod;
    BigEndianUInt64      bookCenterPrice;   // Bn(Price)
};
static_assert(sizeof(OTagTradingStatus) == 18);

// (3) Execution Summary -- K tag (46 bytes)
struct KTagExecutionSummary {
    BigEndianUInt8       messageType;        // 'K'
    BigEndianUInt32      timeMicroseconds;
    AsciiCharString<1>   triggeredSide;      // 'S', 'B', or space (Itayose)
    BigEndianBytes<6>    totalVolume;        // Bn, 6-byte big-endian
    BigEndianBytes<6>    totalInvalidation;  // Bn, 6-byte big-endian
    BigEndianUInt64      lastPrice;          // Bn(Price)
    BigEndianUInt32      matchId;
    BigEndianUInt64      bestOffer;          // Bn(Price)
    BigEndianUInt64      bestBid;            // Bn(Price)
};
static_assert(sizeof(KTagExecutionSummary) == 46);

// (4) Add Order -- A tag (26 bytes)
struct ATagAddOrder {
    BigEndianUInt8       messageType;       // 'A'
    BigEndianUInt32      timeMicroseconds;
    BigEndianUInt32      orderId;
    AsciiCharString<1>   side;              // 'S' or 'B'
    BigEndianBytes<6>    quantity;          // Bn, 6-byte big-endian
    BigEndianUInt64      price;             // Bn(Price); market = UINT64_MAX
    BigEndianUInt8       orderCondition;
    BigEndianUInt8       modificationFlag;
};
static_assert(sizeof(ATagAddOrder) == 26);

// (5) Order Executed -- E tag (20 bytes)
struct ETagOrderExecuted {
    BigEndianUInt8       messageType;       // 'E'
    BigEndianUInt32      timeMicroseconds;
    BigEndianUInt32      orderId;
    AsciiCharString<1>   side;              // 'S' or 'B'
    BigEndianBytes<6>    volume;            // Bn, 6-byte big-endian
    BigEndianUInt32      matchId;
};
static_assert(sizeof(ETagOrderExecuted) == 20);

// (6) Order Executed with Price -- C tag (29 bytes)
struct CTagOrderExecutedWithPrice {
    BigEndianUInt8       messageType;          // 'C'
    BigEndianUInt32      timeMicroseconds;
    BigEndianUInt32      orderId;
    AsciiCharString<1>   side;                 // 'S' or 'B'
    BigEndianBytes<6>    volume;               // Bn, 6-byte big-endian
    BigEndianUInt32      matchId;
    BigEndianUInt64      executionPrice;       // Bn(Price)
    BigEndianUInt8       adoptedPricingMethod;
};
static_assert(sizeof(CTagOrderExecutedWithPrice) == 29);

// (7) Order Delete -- D tag (11 bytes)
struct DTagOrderDelete {
    BigEndianUInt8       messageType;       // 'D'
    BigEndianUInt32      timeMicroseconds;
    BigEndianUInt32      orderId;
    AsciiCharString<1>   side;              // 'S' or 'B'
    BigEndianUInt8       modificationFlag;
};
static_assert(sizeof(DTagOrderDelete) == 11);

// (8) Reset -- R tag (2 bytes)
struct RTagReset {
    BigEndianUInt8   messageType;       // 'R'
    BigEndianUInt8   startEndFlag;      // 1=Start, 2=End
};
static_assert(sizeof(RTagReset) == 2);

// (9) Control -- L tag (3 bytes)
struct LTagControl {
    BigEndianUInt8   messageType;       // 'L'
    BigEndianUInt8   testModeFlag;      // 1=Production, 2=Test
    BigEndianUInt8   startEndFlag;      // 1=Start, 2=End, 0=Health Check
};
static_assert(sizeof(LTagControl) == 3);


PCAPROC_PACK_END

}  // namespace tsembo
