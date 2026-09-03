/**
 * Copyright (c) 2011-2026 libbitcoin developers
 *
 * This file is part of libbitcoin.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_SYSTEM_CHAIN_WITNESS_VIEW_HPP
#define LIBBITCOIN_SYSTEM_CHAIN_WITNESS_VIEW_HPP

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <bitcoin/system/chain/enums/magic_numbers.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/funclets.hpp>

namespace libbitcoin {
namespace system {
namespace chain {

namespace witness_view_detail {

inline size_t remaining(const uint8_t* cursor,
    const uint8_t* stop) NOEXCEPT
{
    return possible_narrow_sign_cast<size_t>(std::distance(cursor, stop));
}

inline bool read_size(size_t& out, const uint8_t*& cursor,
    const uint8_t* stop) NOEXCEPT
{
    if (cursor == stop)
        return false;

    const auto encoded = size_variable(*cursor);
    if (encoded > remaining(cursor, stop))
        return false;

    const auto prefix = *cursor++;
    uint64_t value{};
    if (is_one(encoded))
    {
        value = prefix;
    }
    else
    {
        for (size_t byte{}; byte < sub1(encoded); ++byte)
            value |= static_cast<uint64_t>(*cursor++) << (byte * byte_bits);
    }

    if (variable_size(value) != encoded || value > max_bytes)
        return false;

    out = possible_narrow_cast<size_t>(value);
    return true;
}

inline bool read_element(data_slice& out, const uint8_t*& cursor,
    const uint8_t* stop) NOEXCEPT
{
    size_t size{};
    if (!read_size(size, cursor, stop) || size > remaining(cursor, stop))
        return false;

    const auto next = std::next(cursor, size);
    out = { cursor, next };
    cursor = next;
    return true;
}

} // namespace witness_view_detail

/// Single-pass iterator over the elements of a serialized witness stack.
class BC_API witness_view_iterator final
{
public:
    using difference_type = std::ptrdiff_t;
    using value_type = data_slice;
    using pointer = const data_slice*;
    using reference = const data_slice&;
    using iterator_category = std::input_iterator_tag;

    DEFAULT_COPY_MOVE_DESTRUCT(witness_view_iterator);

    constexpr witness_view_iterator() NOEXCEPT = default;

    witness_view_iterator(const uint8_t* cursor, const uint8_t* stop,
        size_t remaining) NOEXCEPT
      : cursor_(cursor), stop_(stop), remaining_(remaining)
    {
        if (!is_zero(remaining_))
            read_current();
    }

    reference operator*() const NOEXCEPT
    {
        return current_;
    }

    pointer operator->() const NOEXCEPT
    {
        return &current_;
    }

    witness_view_iterator& operator++() NOEXCEPT
    {
        if (is_zero(remaining_))
        {
            terminal_ = true;
            cursor_ = stop_;
        }
        else
        {
            read_current();
        }

        return *this;
    }

    witness_view_iterator operator++(int) NOEXCEPT
    {
        auto copy = *this;
        ++(*this);
        return copy;
    }

    bool operator==(const witness_view_iterator& other) const NOEXCEPT
    {
        return terminal_ == other.terminal_ &&
            cursor_ == other.cursor_ && stop_ == other.stop_ &&
            remaining_ == other.remaining_;
    }

    bool operator!=(const witness_view_iterator& other) const NOEXCEPT
    {
        return !(*this == other);
    }

private:
    void read_current() NOEXCEPT
    {
        if (!witness_view_detail::read_element(current_, cursor_, stop_))
        {
            cursor_ = stop_;
            remaining_ = zero;
            terminal_ = true;
            return;
        }

        --remaining_;
        terminal_ = false;
    }

    const uint8_t* cursor_{};
    const uint8_t* stop_{};
    size_t remaining_{};
    data_slice current_{};
    bool terminal_{ true };
};

/// A validated, allocation-free range over a count-prefixed witness stack.
/// The serialized source must outlive this view and all of its iterators.
class BC_API witness_view final
{
public:
    DEFAULT_COPY_MOVE_DESTRUCT(witness_view);

    using const_iterator = witness_view_iterator;

    constexpr witness_view() NOEXCEPT = default;

    explicit witness_view(const data_slice& witness) NOEXCEPT
      : witness_(witness)
    {
        auto cursor = witness_.begin();
        if (!witness_view_detail::read_size(elements_, cursor,
            witness_.end()))
            return;

        elements_begin_ = cursor;
        for (size_t element{}; element < elements_; ++element)
            if (!witness_view_detail::read_element(element_, cursor,
                witness_.end()))
                return;

        valid_ = cursor == witness_.end();
    }

    constexpr bool is_valid() const NOEXCEPT
    {
        return valid_;
    }

    constexpr const data_slice& data() const NOEXCEPT
    {
        return witness_;
    }

    constexpr size_t size() const NOEXCEPT
    {
        return witness_.size();
    }

    constexpr size_t elements() const NOEXCEPT
    {
        return valid_ ? elements_ : zero;
    }

    constexpr bool empty() const NOEXCEPT
    {
        return is_zero(elements());
    }

    constexpr data_slice annex() const NOEXCEPT
    {
        return elements() > one && !element_.empty() &&
            element_.front() == taproot_annex_prefix ? element_ : data_slice{};
    }

    const_iterator begin() const NOEXCEPT
    {
        return valid_ ? const_iterator{ elements_begin_, witness_.end(),
            elements_ } : end();
    }

    const_iterator end() const NOEXCEPT
    {
        return { witness_.end(), witness_.end(), zero };
    }

private:
    data_slice witness_{};
    const uint8_t* elements_begin_{};
    size_t elements_{};
    data_slice element_{};
    bool valid_{ false };
};

} // namespace chain
} // namespace system
} // namespace libbitcoin

#endif
