#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace pcaproc {

// BigEndianInteger<T>
//
// A trivially-copyable, standard-layout wrapper around an integer of type `T`
// stored in network (big-endian) byte order. Its size and layout are exactly
// `sizeof(T)` contiguous bytes with no padding, so instances can be safely
// overlaid onto on-the-wire message structures (e.g. via reinterpret_cast on a
// received buffer, or as a member of a packed struct describing a protocol
// header).
//
// Example:
//   struct UdpHeader {
//       BigEndianInteger<std::uint16_t> src_port;
//       BigEndianInteger<std::uint16_t> dst_port;
//       BigEndianInteger<std::uint16_t> length;
//       BigEndianInteger<std::uint16_t> checksum;
//   };
//   static_assert(sizeof(UdpHeader) == 8);
//
//   auto* h = reinterpret_cast<const UdpHeader*>(buffer);
//   std::uint16_t sport = h->src_port.value();
//
template <typename T>
class BigEndianInteger {
    static_assert(std::is_integral<T>::value, "T must be an integral type");
    static_assert(!std::is_same<T, bool>::value, "bool is not supported");

public:
    using value_type = T;
    static constexpr std::size_t byte_size = sizeof(T);

    // Default-constructed value is zero (all bytes 0).
    BigEndianInteger() noexcept : bytes_{} {}

    // Construct from a native (host-order) value.
    explicit BigEndianInteger(T v) noexcept { store(v); }

    // Assignment from a native value.
    BigEndianInteger& operator=(T v) noexcept {
        store(v);
        return *this;
    }

    // Read the value in host byte order.
    T value() const noexcept { return load(); }

    // Implicit conversion to the underlying native type, for ergonomic use
    // (e.g. `if (header.length > 64) {...}`).
    operator T() const noexcept { return load(); }  // NOLINT(google-explicit-constructor)

    // Set the value from a native (host-order) integer.
    void set(T v) noexcept { store(v); }

    // Raw byte access (big-endian, exactly as on the wire).
    const unsigned char* data() const noexcept { return bytes_; }
    unsigned char* data() noexcept { return bytes_; }
    static constexpr std::size_t size() noexcept { return byte_size; }

    // Equality compares the underlying integer value.
    friend bool operator==(const BigEndianInteger& a, const BigEndianInteger& b) noexcept {
        return std::memcmp(a.bytes_, b.bytes_, byte_size) == 0;
    }
    friend bool operator!=(const BigEndianInteger& a, const BigEndianInteger& b) noexcept {
        return !(a == b);
    }

private:
    // Use unsigned arithmetic for byte assembly to avoid sign-extension issues,
    // then cast back to T at the end. This works for both signed and unsigned T.
    using UT = typename std::make_unsigned<T>::type;

    T load() const noexcept {
        UT v = 0;
        for (std::size_t i = 0; i < byte_size; ++i) {
            v = static_cast<UT>((v << 8) | static_cast<UT>(bytes_[i]));
        }
        return static_cast<T>(v);
    }

    void store(T value) noexcept {
        UT v = static_cast<UT>(value);
        for (std::size_t i = 0; i < byte_size; ++i) {
            bytes_[byte_size - 1 - i] = static_cast<unsigned char>(v & 0xFFu);
            v = static_cast<UT>(v >> 8);
        }
    }

    unsigned char bytes_[byte_size];
};

// Layout guarantees that make overlay-onto-wire-buffer usage safe.
static_assert(sizeof(BigEndianInteger<std::uint16_t>) == 2,
              "BigEndianInteger must have no padding");
static_assert(sizeof(BigEndianInteger<std::uint32_t>) == 4,
              "BigEndianInteger must have no padding");
static_assert(sizeof(BigEndianInteger<std::uint64_t>) == 8,
              "BigEndianInteger must have no padding");
static_assert(std::is_trivially_copyable<BigEndianInteger<std::uint32_t>>::value,
              "BigEndianInteger must be trivially copyable");
static_assert(std::is_standard_layout<BigEndianInteger<std::uint32_t>>::value,
              "BigEndianInteger must be standard layout");

// Convenient aliases for the most common wire-format widths.
using BigEndianInt8   = BigEndianInteger<std::int8_t>;
using BigEndianUInt8  = BigEndianInteger<std::uint8_t>;
using BigEndianInt16  = BigEndianInteger<std::int16_t>;
using BigEndianUInt16 = BigEndianInteger<std::uint16_t>;
using BigEndianInt32  = BigEndianInteger<std::int32_t>;
using BigEndianUInt32 = BigEndianInteger<std::uint32_t>;
using BigEndianInt64  = BigEndianInteger<std::int64_t>;
using BigEndianUInt64 = BigEndianInteger<std::uint64_t>;

// BigEndianBytes<N>
//
// Fixed-size big-endian unsigned integer field of `N` bytes (1..8), stored
// as exactly `N` contiguous bytes with no padding. Use this for wire fields
// whose width is not one of the standard integer sizes (e.g. 3-, 5-, 6- or
// 7-byte big-endian quantities found in some exchange protocols).
//
// Decoded with `value()` into a `std::uint64_t` in host byte order.
template <std::size_t N>
struct BigEndianBytes {
    static_assert(N >= 1 && N <= 8, "BigEndianBytes<N>: N must be in [1,8]");
    unsigned char bytes[N];

    std::uint64_t value() const noexcept {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < N; ++i) {
            v = (v << 8) | static_cast<std::uint64_t>(bytes[i]);
        }
        return v;
    }
    operator std::uint64_t() const noexcept { return value(); }  // NOLINT(google-explicit-constructor)
};
static_assert(sizeof(BigEndianBytes<3>) == 3, "BigEndianBytes must be packed");
static_assert(sizeof(BigEndianBytes<6>) == 6, "BigEndianBytes must be packed");
static_assert(std::is_trivially_copyable<BigEndianBytes<6>>::value,
              "BigEndianBytes must be trivially copyable");
static_assert(std::is_standard_layout<BigEndianBytes<6>>::value,
              "BigEndianBytes must be standard layout");

}  // namespace pcaproc
