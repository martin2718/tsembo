#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <iostream>
#include <string>
#include <unordered_map>

#include "IndicativeVolumeBook.hpp"
#include "MessageParser.hpp"
#include "Messages.hpp"
#include "PcapLoader.hpp"

namespace {

// Per-issue state: live order book plus the most recent Itayose reference
// price (book center price published in O tags). Indicative volume is
// computed from the live book at reporting time.
struct IssueState {
    pcaproc::IndicativeVolumeBook book;
    bool          have_price = false;
    std::uint64_t last_price = 0;
};

// Pretty-print a Bn(Price) value. Per arrowhead FLEX spec sec. 3.1.1 the
// last four digits of a Bn(Price) value are decimal fractions, so the
// displayed price is `wire_value / 10000`.
void format_price(std::uint64_t wire_price, char* buf, std::size_t buf_size) {
    constexpr std::uint64_t kScale = 10000;
    const std::uint64_t whole = wire_price / kScale;
    const std::uint64_t frac  = wire_price % kScale;
    std::snprintf(buf, buf_size, "%llu.%04llu",
                  static_cast<unsigned long long>(whole),
                  static_cast<unsigned long long>(frac));
}

// Derive an output CSV path from the input pcap path: strip a trailing
// `.pcap` (case-insensitive) extension if present, then append `.csv`.
std::string csv_path_for(const std::string& pcap_path) {
    std::string base = pcap_path;
    const auto dot   = base.find_last_of('.');
    const auto slash = base.find_last_of("/\\");
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash)) {
        std::string ext = base.substr(dot + 1);
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext == "pcap") base.resize(dot);
    }
    base += ".csv";
    return base;
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [-d] <file.pcap>\n"
              << "  Reads UDP payloads, parses arrowhead FLEX MBO tags,\n"
              << "  maintains a per-issue order book, and reports the last\n"
              << "  observed indicative price + volume per security.\n"
              << "\n"
              << "  -d   Also print a human-readable table to stdout.\n"
              << "       The CSV file is always written.\n";
}

}  // namespace

int main(int argc, char** argv) {
    bool display_mode = false;
    const char* pcap_path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-d") == 0) {
            display_mode = true;
        } else if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (pcap_path == nullptr) {
            pcap_path = argv[i];
        } else {
            std::cerr << "Unexpected argument: " << argv[i] << '\n';
            print_usage(argv[0]);
            return 2;
        }
    }
    if (pcap_path == nullptr) {
        print_usage(argv[0]);
        return 0;
    }

    pcaproc::PcapLoader loader;
    if (!loader.open(pcap_path)) {
        std::cerr << "Failed to open " << pcap_path << ": " << loader.last_error() << '\n';
        return 1;
    }

    pcaproc::MessageParser parser;
    std::unordered_map<std::string, IssueState> by_issue;

    const long n = loader.for_each_udp([&](const pcaproc::UdpPayload& pkt) {
        parser.parse(pkt.data.data(), pkt.data.size(),
                     [&](const pcaproc::PacketHeader& hdr,
                         const pcaproc::TagView& v) {
            // R tag (Reset) carries no issueCode -- apply globally.
            if (v.tag == pcaproc::TagType::Reset) {
                if (v.raw_size == sizeof(pcaproc::RTagReset) + 1) {
                    const auto* r = reinterpret_cast<const pcaproc::RTagReset*>(v.raw + 1);
                    if (r->startEndFlag.value() == 1) {
                        for (auto& kv : by_issue) {
                            kv.second.book.reset();
                            kv.second.have_price = false;
                        }
                    }
                }
                return;
            }
            if (v.tag == pcaproc::TagType::Control) {
                return;
            }

            const std::string issue = hdr.issueCode.trimmed();
            if (issue.empty()) return;

            auto& state = by_issue[issue];
            state.book.apply(v);

            // The Itayose O tag announces the auction reference price.
            // The crossing volume is computed from the live book at end of
            // run (orders accumulate after the O tag).
            if (v.tag == pcaproc::TagType::TradingStatus &&
                v.raw_size == sizeof(pcaproc::OTagTradingStatus) + 1) {
                const auto* o =
                    reinterpret_cast<const pcaproc::OTagTradingStatus*>(v.raw + 1);
                if (o->pricingMethod.value() == 1 /* Itayose */) {
                    state.last_price = o->bookCenterPrice.value();
                    state.have_price = true;
                }
            }
        });
    });

    if (n < 0) {
        std::cerr << "Error while reading pcap: " << loader.last_error() << '\n';
        return 1;
    }

    if (display_mode) {
        std::printf("%-14s %18s %16s\n", "IssueCode", "IndicativePrice", "IndicativeVol");
        std::printf("%-14s %18s %16s\n", "---------", "---------------", "-------------");
        for (const auto& kv : by_issue) {
            const auto& s = kv.second;
            if (!s.have_price) {
                std::printf("%-14s %18s %16s\n", kv.first.c_str(), "(none)", "(none)");
                continue;
            }
            const auto vol = s.book.indicative_volume_at(s.last_price);
            char pricebuf[32];
            format_price(s.last_price, pricebuf, sizeof(pricebuf));
            std::printf("%-14s %18s %16llu\n",
                        kv.first.c_str(),
                        pricebuf,
                        static_cast<unsigned long long>(vol));
        }
    }

    const std::string csv_path = csv_path_for(pcap_path);
    std::FILE* csv = std::fopen(csv_path.c_str(), "w");
    if (csv == nullptr) {
        std::cerr << "Failed to open output CSV " << csv_path << ": "
                  << std::strerror(errno) << '\n';
        return 1;
    }
    std::fprintf(csv, "symbol,iap,iav\n");
    for (const auto& kv : by_issue) {
        const auto& s = kv.second;
        if (!s.have_price) {
            std::fprintf(csv, "%s,,\n", kv.first.c_str());
            continue;
        }
        const auto vol = s.book.indicative_volume_at(s.last_price);
        char pricebuf[32];
        format_price(s.last_price, pricebuf, sizeof(pricebuf));
        std::fprintf(csv, "%s,%s,%llu\n",
                     kv.first.c_str(),
                     pricebuf,
                     static_cast<unsigned long long>(vol));
    }
    std::fclose(csv);
    std::cerr << "Wrote " << by_issue.size() << " issues to " << csv_path << '\n';

    return 0;
}
