#pragma once

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <type_traits>

namespace pcaproc {

// AsciiCharString<N>
//
// A fixed-size, trivially-copyable, standard-layout ASCII string of exactly
// `N` bytes. Designed to be overlaid on on-the-wire message structures to
// extract / populate string fields:
//
//   struct LoginMessage {
//       AsciiCharString<8>  username;
//       AsciiCharString<16> password;
//   };
//   static_assert(sizeof(LoginMessage) == 24);
//
//   auto* msg = reinterpret_cast<const LoginMessage*>(buffer);
//   std::string user = msg->username.str();
//
// Wire conventions vary by protocol: some pad short strings with NUL bytes,
// others pad with spaces. `str()` returns characters up to the first NUL (or
// all N bytes if no NUL is present). `trimmed()` additionally strips trailing
// spaces, which is convenient for FIX-style fixed-width fields.
template <std::size_t N>
class AsciiCharString {
    static_assert(N > 0, "AsciiCharString size must be greater than zero");

public:
    static constexpr std::size_t byte_size = N;

    // Default-constructed value is all NUL bytes.
    AsciiCharString() noexcept : bytes_{} {}

    // Construct from a C-string. Copies up to N characters; remaining bytes
    // are filled with NUL. Does not require a terminating NUL in the source
    // when its length already meets N.
    explicit AsciiCharString(const char* s) noexcept : bytes_{} { assign(s); }

    // Construct from std::string. Excess characters beyond N are discarded;
    // remaining bytes are filled with NUL.
    explicit AsciiCharString(const std::string& s) noexcept : bytes_{} {
        assign(s.data(), s.size());
    }

    AsciiCharString& operator=(const char* s) noexcept {
        assign(s);
        return *this;
    }
    AsciiCharString& operator=(const std::string& s) noexcept {
        assign(s.data(), s.size());
        return *this;
    }

    // Copy `len` bytes (or up to N, whichever is smaller) into the field,
    // NUL-padding any remainder.
    void assign(const char* src, std::size_t len) noexcept {
        const std::size_t n = (len < N) ? len : N;
        if (n > 0 && src != nullptr) {
            std::memcpy(bytes_, src, n);
        }
        if (n < N) {
            std::memset(bytes_ + n, 0, N - n);
        }
    }

    // Copy from a NUL-terminated C string.
    void assign(const char* src) noexcept {
        if (!src) {
            std::memset(bytes_, 0, N);
            return;
        }
        assign(src, std::strlen(src));
    }

    // Pad-fill the entire field with `pad` (e.g. ' ' for FIX-style fields).
    void fill(char pad) noexcept { std::memset(bytes_, static_cast<unsigned char>(pad), N); }

    // Raw byte access (exactly as on the wire).
    const char* data() const noexcept { return bytes_; }
    char* data() noexcept { return bytes_; }
    static constexpr std::size_t size() noexcept { return N; }

    // Element access (no bounds checking, matching std::array semantics).
    char operator[](std::size_t i) const noexcept { return bytes_[i]; }
    char& operator[](std::size_t i) noexcept { return bytes_[i]; }

    // Length of the embedded C-string (characters up to the first NUL, or N
    // if no NUL byte is present).
    std::size_t length() const noexcept {
        const void* p = std::memchr(bytes_, 0, N);
        return p ? static_cast<std::size_t>(static_cast<const char*>(p) - bytes_) : N;
    }

    bool empty() const noexcept { return bytes_[0] == '\0'; }

    // Convert to std::string, stopping at the first NUL (or returning all N
    // bytes if there is no NUL).
    std::string str() const { return std::string(bytes_, length()); }

    // Like str() but additionally trims trailing ASCII spaces.
    std::string trimmed() const {
        std::size_t end = length();
        while (end > 0 && bytes_[end - 1] == ' ') {
            --end;
        }
        return std::string(bytes_, end);
    }

    // Byte-wise equality (compares the full N-byte buffer).
    friend bool operator==(const AsciiCharString& a, const AsciiCharString& b) noexcept {
        return std::memcmp(a.bytes_, b.bytes_, N) == 0;
    }
    friend bool operator!=(const AsciiCharString& a, const AsciiCharString& b) noexcept {
        return !(a == b);
    }

private:
    char bytes_[N];
};

// Layout guarantees that make overlay-onto-wire-buffer usage safe.
static_assert(sizeof(AsciiCharString<1>) == 1, "AsciiCharString must have no padding");
static_assert(sizeof(AsciiCharString<7>) == 7, "AsciiCharString must have no padding");
static_assert(sizeof(AsciiCharString<32>) == 32, "AsciiCharString must have no padding");
static_assert(std::is_trivially_copyable<AsciiCharString<16>>::value,
              "AsciiCharString must be trivially copyable");
static_assert(std::is_standard_layout<AsciiCharString<16>>::value,
              "AsciiCharString must be standard layout");

}  // namespace pcaproc
