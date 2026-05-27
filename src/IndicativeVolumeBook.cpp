#include "IndicativeVolumeBook.hpp"

namespace pcaproc {

void IndicativeVolumeBook::reset() {
    orders_.clear();
    bids_.clear();
    asks_.clear();
    market_bid_qty_ = 0;
    market_ask_qty_ = 0;
}

void IndicativeVolumeBook::add_to_aggregate(char side, Price price, Quantity qty) {
    if (price == kMarketOrder) {
        if (side == 'B') market_bid_qty_ += qty;
        else             market_ask_qty_ += qty;
        return;
    }
    if (side == 'B') bids_[price] += qty;
    else             asks_[price] += qty;
}

void IndicativeVolumeBook::sub_from_aggregate(char side, Price price, Quantity qty) {
    if (price == kMarketOrder) {
        if (side == 'B') {
            market_bid_qty_ = (qty >= market_bid_qty_) ? 0 : market_bid_qty_ - qty;
        } else {
            market_ask_qty_ = (qty >= market_ask_qty_) ? 0 : market_ask_qty_ - qty;
        }
        return;
    }
    if (side == 'B') {
        auto it = bids_.find(price);
        if (it == bids_.end()) return;
        if (qty >= it->second) bids_.erase(it);
        else                   it->second -= qty;
    } else {
        auto it = asks_.find(price);
        if (it == asks_.end()) return;
        if (qty >= it->second) asks_.erase(it);
        else                   it->second -= qty;
    }
}

bool IndicativeVolumeBook::apply_add(const ATagAddOrder& a) {
    const char side = a.side[0];
    if (side != 'B' && side != 'S') return false;

    const OrderId id  = static_cast<OrderId>(a.orderId.value());
    const Price   px  = a.price.value();
    const Quantity q  = a.quantity.value();

    // The spec says an A tag with modificationFlag == 1 represents a
    // quantity-reduction style modification (no change to time priority);
    // either way the latest A tag carries the *current* resting quantity
    // for that orderId, so we treat it as an upsert.
    auto it = orders_.find(id);
    if (it != orders_.end()) {
        sub_from_aggregate(it->second.side, it->second.price, it->second.qty);
        it->second = Order{side, px, q};
    } else {
        orders_.emplace(id, Order{side, px, q});
    }
    add_to_aggregate(side, px, q);
    return true;
}

bool IndicativeVolumeBook::apply_delete(const DTagOrderDelete& d) {
    const OrderId id = static_cast<OrderId>(d.orderId.value());
    auto it = orders_.find(id);
    if (it == orders_.end()) return false;
    sub_from_aggregate(it->second.side, it->second.price, it->second.qty);
    orders_.erase(it);
    return true;
}

bool IndicativeVolumeBook::apply_executed(OrderId order_id, Quantity volume) {
    auto it = orders_.find(order_id);
    if (it == orders_.end()) return false;
    Quantity exec = (volume > it->second.qty) ? it->second.qty : volume;
    sub_from_aggregate(it->second.side, it->second.price, exec);
    it->second.qty -= exec;
    if (it->second.qty == 0) {
        orders_.erase(it);
    }
    return true;
}

bool IndicativeVolumeBook::apply(const TagView& tag) {
    // Each FLEX MBO tag struct includes the leading Message Type byte, so
    // `raw_size` (which counts the length byte too) must equal
    // sizeof(TagBody) + 1.
    switch (tag.tag) {
        case TagType::AddOrder: {
            if (tag.raw_size != sizeof(ATagAddOrder) + 1) return false;
            const auto* a = reinterpret_cast<const ATagAddOrder*>(tag.raw + 1);
            return apply_add(*a);
        }
        case TagType::OrderDelete: {
            if (tag.raw_size != sizeof(DTagOrderDelete) + 1) return false;
            const auto* d = reinterpret_cast<const DTagOrderDelete*>(tag.raw + 1);
            return apply_delete(*d);
        }
        case TagType::OrderExecuted: {
            if (tag.raw_size != sizeof(ETagOrderExecuted) + 1) return false;
            const auto* e = reinterpret_cast<const ETagOrderExecuted*>(tag.raw + 1);
            return apply_executed(static_cast<OrderId>(e->orderId.value()),
                                  e->volume.value());
        }
        case TagType::OrderExecutedWithPrice: {
            if (tag.raw_size != sizeof(CTagOrderExecutedWithPrice) + 1) return false;
            const auto* c = reinterpret_cast<const CTagOrderExecutedWithPrice*>(tag.raw + 1);
            return apply_executed(static_cast<OrderId>(c->orderId.value()),
                                  c->volume.value());
        }
        case TagType::Reset: {
            if (tag.raw_size != sizeof(RTagReset) + 1) return false;
            const auto* r = reinterpret_cast<const RTagReset*>(tag.raw + 1);
            if (r->startEndFlag.value() == 1) {
                reset();
                return true;
            }
            return false;
        }
        default:
            return false;
    }
}

std::size_t IndicativeVolumeBook::apply_payload(MessageParser& parser,
                                                const std::uint8_t* data,
                                                std::size_t size) {
    std::size_t applied = 0;
    parser.parse(data, size, [&](const PacketHeader&, const TagView& v) {
        if (apply(v)) ++applied;
    });
    return applied;
}

IndicativeVolumeBook::Quantity
IndicativeVolumeBook::buy_quantity_at_or_above(Price price) const {
    Quantity total = market_bid_qty_;
    if (price == kMarketOrder) {
        // Only market buys cross with a market sell; limit buys do not have
        // an "at or above market" interpretation.
        return total;
    }
    // bids_ is sorted descending; iterate until level drops below `price`.
    for (const auto& kv : bids_) {
        if (kv.first < price) break;
        total += kv.second;
    }
    return total;
}

IndicativeVolumeBook::Quantity
IndicativeVolumeBook::sell_quantity_at_or_below(Price price) const {
    Quantity total = market_ask_qty_;
    if (price == kMarketOrder) {
        return total;
    }
    // asks_ is sorted ascending; iterate until level exceeds `price`.
    for (const auto& kv : asks_) {
        if (kv.first > price) break;
        total += kv.second;
    }
    return total;
}

IndicativeVolumeBook::Quantity
IndicativeVolumeBook::indicative_volume_at(Price price) const {
    Quantity buy_total;
    Quantity sell_total;
    if (price == kMarketOrder) {
        // Treat as "any price crosses": all limit orders are marketable.
        buy_total  = market_bid_qty_;
        sell_total = market_ask_qty_;
        for (const auto& kv : bids_) buy_total  += kv.second;
        for (const auto& kv : asks_) sell_total += kv.second;
    } else {
        buy_total  = buy_quantity_at_or_above(price);
        sell_total = sell_quantity_at_or_below(price);
    }
    return (buy_total < sell_total) ? buy_total : sell_total;
}

}  // namespace pcaproc
