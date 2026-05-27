#pragma once

#include "MessageParser.hpp"
#include "Messages.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <unordered_map>

namespace pcaproc {

// IndicativeVolumeBook
//
// Maintains a per-issue order book from the arrowhead FLEX Market-by-Order
// tag stream and derives the indicative cross volume at a reference price.
//
// During the opening (or any Itayose) auction, the MBO feed does not publish
// an "indicative matched volume" field. Instead the spec exposes only the
// indicative price via `OTagTradingStatus::bookCenterPrice` (when
// `pricingMethod == 1`, Itayose). The matched volume that *would* cross at
// that price must be computed client-side from the live order book.
//
// This class consumes the tags relevant to the book and answers the
// "indicative volume at price P" question by counting the marketable
// quantity on each side at P:
//
//     buy_qty  = sum(qty of buy  orders with price >= P) + market buys
//     sell_qty = sum(qty of sell orders with price <= P) + market sells
//     indicative_volume(P) = min(buy_qty, sell_qty)
//
// Tags consumed:
//
//   A tag  upsert order (orderId, side, price, qty)
//   D tag  delete order (orderId)
//   E tag  Zaraba execution: reduce order's remaining qty by `volume`
//   C tag  Itayose execution: reduce order's remaining qty by `volume`
//   R tag  reset (clear the whole book) on startEndFlag == 1
//
// All other tags (T/O/K/L and any future tag) are ignored by this class.
// One instance corresponds to a single issue; route tags per issueCode
// upstream if you maintain multiple books.
class IndicativeVolumeBook {
public:
    using Price    = std::uint64_t;
    using Quantity = std::uint64_t;
    using OrderId  = std::uint32_t;

    // Sentinel used by the A tag's price field for market orders
    // (spec: "For market orders, this will be set to the maximum value (64bit).")
    static constexpr Price kMarketOrder = std::numeric_limits<Price>::max();

    IndicativeVolumeBook() = default;

    // Drop all state. Called automatically when an R tag with
    // startEndFlag == 1 is applied.
    void reset();

    // Apply one submessage; returns true if it was relevant to the book.
    // The TagView may originate from a `MessageParser` callback. Bodies
    // are validated for size before being decoded; oversize/undersize tags
    // are ignored.
    bool apply(const TagView& tag);

    // Convenience: apply all tags in `payload`, using `parser` to decode.
    // Returns the number of book-relevant tags applied.
    std::size_t apply_payload(MessageParser& parser,
                              const std::uint8_t* data, std::size_t size);

    // Compute the indicative cross volume if a match occurred at `price`.
    // For `price == kMarketOrder`, all limit orders on both sides are
    // considered marketable and the result is min(total_buy, total_sell).
    Quantity indicative_volume_at(Price price) const;

    // Marketable buy quantity at the given price (limits with price >= P,
    // plus all market buys). Both totals are 0 when the book is empty.
    Quantity buy_quantity_at_or_above(Price price) const;

    // Marketable sell quantity at the given price (limits with price <= P,
    // plus all market sells).
    Quantity sell_quantity_at_or_below(Price price) const;

    // Distinct price levels currently on each side (market orders are not
    // counted as a price level).
    std::size_t bid_levels() const { return bids_.size(); }
    std::size_t ask_levels() const { return asks_.size(); }

    // Number of resting orders tracked.
    std::size_t order_count() const { return orders_.size(); }

private:
    struct Order {
        char     side;   // 'B' or 'S'
        Price    price;  // kMarketOrder for market orders
        Quantity qty;
    };

    // Apply concrete tag bodies. Each returns true on success.
    bool apply_add(const ATagAddOrder& a);
    bool apply_delete(const DTagOrderDelete& d);
    bool apply_executed(OrderId order_id, Quantity volume);

    void add_to_aggregate(char side, Price price, Quantity qty);
    void sub_from_aggregate(char side, Price price, Quantity qty);

    // Per-order state, keyed by Order ID.
    std::unordered_map<OrderId, Order> orders_;

    // Aggregate resting quantity per limit price, kept ordered so we can
    // walk from the marketable side in O(levels touched).
    std::map<Price, Quantity, std::greater<Price>> bids_;  // descending
    std::map<Price, Quantity>                      asks_;  // ascending

    // Market-order aggregates (always crossable).
    Quantity market_bid_qty_ = 0;
    Quantity market_ask_qty_ = 0;
};

}  // namespace pcaproc
