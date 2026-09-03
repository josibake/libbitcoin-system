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
#ifndef LIBBITCOIN_SYSTEM_CHAIN_SCRIPT_VIEW_HPP
#define LIBBITCOIN_SYSTEM_CHAIN_SCRIPT_VIEW_HPP

#include <cstddef>
#include <iterator>
#include <span>
#include <bitcoin/system/chain/enums/magic_numbers.hpp>
#include <bitcoin/system/chain/enums/opcode.hpp>
#include <bitcoin/system/chain/operation.hpp>
#include <bitcoin/system/constants.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/math/math.hpp>
#include <bitcoin/system/stream/stream.hpp>

namespace libbitcoin {
namespace system {
namespace chain {

/// A non-owning view of one serialized script operation.
class BC_API operation_view final
{
public:
    DEFAULT_COPY_MOVE_DESTRUCT(operation_view);

    constexpr operation_view() NOEXCEPT = default;
    constexpr operation_view(opcode code, const data_slice& data,
        const data_slice& raw, size_t offset, size_t position,
        bool underflow) NOEXCEPT
      : code_(code), data_(data), raw_(raw), offset_(offset),
        position_(position), underflow_(underflow)
    {
    }

    constexpr opcode code() const NOEXCEPT
    {
        return code_;
    }

    constexpr const data_slice& data() const NOEXCEPT
    {
        return data_;
    }

    constexpr const data_slice& raw() const NOEXCEPT
    {
        return raw_;
    }

    constexpr size_t offset() const NOEXCEPT
    {
        return offset_;
    }

    constexpr size_t next_offset() const NOEXCEPT
    {
        return ceilinged_add(offset_, raw_.size());
    }

    constexpr size_t position() const NOEXCEPT
    {
        return position_;
    }

    constexpr bool is_underclaimed() const NOEXCEPT
    {
        return data_.size() > operation::opcode_to_maximum_size(code_);
    }

    constexpr bool is_oversized() const NOEXCEPT
    {
        return data_.size() > max_push_data_size;
    }

    constexpr bool is_underflow() const NOEXCEPT
    {
        return underflow_;
    }

    constexpr bool is_conditional() const NOEXCEPT
    {
        return operation::is_conditional(code_);
    }

private:
    opcode code_{ opcode::op_verif };
    data_slice data_{};
    data_slice raw_{};
    size_t offset_{};
    size_t position_{};
    bool underflow_{ false };
};

/// Single-pass parser over a serialized script. The source must outlive it.
class BC_API operation_view_iterator final
{
public:
    using difference_type = std::ptrdiff_t;
    using value_type = operation_view;
    using pointer = const operation_view*;
    using reference = const operation_view&;
    using iterator_category = std::input_iterator_tag;

    DEFAULT_COPY_MOVE_DESTRUCT(operation_view_iterator);

    constexpr operation_view_iterator() NOEXCEPT = default;

    operation_view_iterator(const uint8_t* cursor,
        const uint8_t* stop) NOEXCEPT
      : begin_(cursor), cursor_(cursor), stop_(stop), terminal_(cursor == stop)
    {
        if (!terminal_)
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

    operation_view_iterator& operator++() NOEXCEPT
    {
        if (cursor_ == stop_)
            terminal_ = true;
        else
            read_current();

        return *this;
    }

    operation_view_iterator operator++(int) NOEXCEPT
    {
        auto copy = *this;
        ++(*this);
        return copy;
    }

    bool operator==(const operation_view_iterator& other) const NOEXCEPT
    {
        return terminal_ == other.terminal_ &&
            cursor_ == other.cursor_ && stop_ == other.stop_;
    }

    bool operator!=(const operation_view_iterator& other) const NOEXCEPT
    {
        return !(*this == other);
    }

private:
    size_t remaining() const NOEXCEPT
    {
        return possible_narrow_sign_cast<size_t>(std::distance(cursor_, stop_));
    }

    bool read_little(size_t& out, size_t bytes) NOEXCEPT
    {
        out = {};
        if (bytes > remaining())
            return false;

        for (size_t byte{}; byte < bytes; ++byte)
            out |= static_cast<size_t>(*cursor_++) << (byte * byte_bits);

        return true;
    }

    bool read_size(size_t& out, opcode code) NOEXCEPT
    {
        constexpr auto op75 = static_cast<uint8_t>(opcode::push_size_75);

        switch (code)
        {
            case opcode::push_one_size:
                return read_little(out, sizeof(uint8_t));
            case opcode::push_two_size:
                return read_little(out, sizeof(uint16_t));
            case opcode::push_four_size:
                return read_little(out, sizeof(uint32_t));
            default:
                out = static_cast<uint8_t>(code) <= op75 ?
                    static_cast<uint8_t>(code) : zero;
                return true;
        }
    }

    void read_current() NOEXCEPT
    {
        const auto start = cursor_;
        const auto offset = possible_narrow_sign_cast<size_t>(
            std::distance(begin_, start));
        const auto code = static_cast<opcode>(*cursor_++);
        size_t size{};

        if (!read_size(size, code) || size > max_bytes || size > remaining())
        {
            const data_slice tail{ start, stop_ };
            current_ = { opcode::op_verif, tail, tail, offset,
                position_++, true };
            cursor_ = stop_;
            return;
        }

        const auto next = std::next(cursor_, size);
        current_ = { code, data_slice{ cursor_, next },
            data_slice{ start, next }, offset, position_++, false };
        cursor_ = next;
    }

    const uint8_t* begin_{};
    const uint8_t* cursor_{};
    const uint8_t* stop_{};
    size_t position_{};
    operation_view current_{};
    bool terminal_{ true };
};

/// A non-owning, allocation-free range over serialized script operations.
/// The source buffer must outlive this view and all iterators obtained from it.
class BC_API script_view final
{
public:
    DEFAULT_COPY_MOVE_DESTRUCT(script_view);

    using const_iterator = operation_view_iterator;

    constexpr script_view() NOEXCEPT = default;
    explicit script_view(const data_slice& script) NOEXCEPT
      : script_(script), valid_(true)
    {
        for (const auto& op: *this)
        {
            prevalid_ |= operation::is_success(op.code());
            prefail_ |= operation::is_invalid(op.code());
            roller_ |= operation::is_roller(op.code());
            underflow_ |= op.is_underflow();
        }
    }

    constexpr bool is_valid() const NOEXCEPT
    {
        return valid_;
    }

    constexpr bool is_roller() const NOEXCEPT
    {
        return roller_;
    }

    constexpr bool is_prefail() const NOEXCEPT
    {
        return prefail_;
    }

    constexpr bool is_prevalid() const NOEXCEPT
    {
        return prevalid_;
    }

    constexpr bool is_underflow() const NOEXCEPT
    {
        return underflow_;
    }

    constexpr bool is_oversized() const NOEXCEPT
    {
        return script_.size() > max_script_size;
    }

    constexpr const data_slice& data() const NOEXCEPT
    {
        return script_;
    }

    constexpr size_t size() const NOEXCEPT
    {
        return script_.size();
    }

    constexpr bool empty() const NOEXCEPT
    {
        return script_.empty();
    }

    constexpr size_t serialized_size(bool prefix) const NOEXCEPT
    {
        return ceilinged_add(script_.size(),
            prefix ? variable_size(script_.size()) : zero);
    }

    void to_data(writer& sink, bool prefix) const NOEXCEPT
    {
        if (prefix)
            sink.write_variable(script_.size());

        sink.write_bytes(script_);
    }

    const_iterator begin() const NOEXCEPT
    {
        return { script_.begin(), script_.end() };
    }

    const_iterator begin(size_t offset) const NOEXCEPT
    {
        BC_ASSERT(offset <= script_.size());
        return { std::next(script_.begin(), offset), script_.end() };
    }

    const_iterator end() const NOEXCEPT
    {
        return { script_.end(), script_.end() };
    }

    constexpr const script_view& ops() const NOEXCEPT
    {
        return *this;
    }

private:
    data_slice script_{};
    bool valid_{ false };
    bool roller_{ false };
    bool prefail_{ false };
    bool prevalid_{ false };
    bool underflow_{ false };
};

/// A serialized subscript over archive bytes. The script, endorsements, and
/// their backing buffers must outlive this view. Unversioned signature hashing
/// strips code separators and nominal endorsement pushes; the two-argument
/// form preserves the serialized script unchanged for version 0.
class BC_API script_subview final
{
public:
    DEFAULT_COPY_MOVE_DESTRUCT(script_subview);

    constexpr script_subview() NOEXCEPT = default;

    constexpr script_subview(const script_view& script, size_t offset) NOEXCEPT
      : script_(script), offset_(offset)
    {
    }

    constexpr script_subview(const script_view& script, size_t offset,
        const data_slice& endorsement) NOEXCEPT
      : script_(script), offset_(offset), strip_(true),
        endorsement_(endorsement), single_(true)
    {
    }

    constexpr script_subview(const script_view& script, size_t offset,
        std::span<const data_slice> endorsements) NOEXCEPT
      : script_(script), offset_(offset), strip_(true),
        endorsements_(endorsements)
    {
    }

    size_t serialized_size(bool prefix) const NOEXCEPT
    {
        const auto size = body_size();
        return ceilinged_add(size, prefix ? variable_size(size) : zero);
    }

    void to_data(writer& sink, bool prefix) const NOEXCEPT
    {
        const auto size = body_size();

        if (prefix)
            sink.write_variable(size);

        if (!strip_)
        {
            sink.write_bytes(body());
            return;
        }

        for (auto op = script_.begin(offset_); op != script_.end(); ++op)
            if (!is_stripped(*op))
                sink.write_bytes(op->raw());
    }

private:
    data_slice body() const NOEXCEPT
    {
        BC_ASSERT(offset_ <= script_.size());
        return { std::next(script_.data().begin(), offset_),
            script_.data().end() };
    }

    size_t body_size() const NOEXCEPT
    {
        if (!strip_)
            return body().size();

        size_t size{};
        for (auto op = script_.begin(offset_); op != script_.end(); ++op)
            if (!is_stripped(*op))
                size = ceilinged_add(size, op->raw().size());

        return size;
    }

    bool is_stripped(const operation_view& op) const NOEXCEPT
    {
        if (op.code() == opcode::codeseparator)
            return true;

        if (single_ &&
            op.code() == operation::opcode_from_size(endorsement_.size()) &&
            op.data() == endorsement_)
            return true;

        for (const auto& endorsement: endorsements_)
            if (op.code() == operation::opcode_from_size(endorsement.size()) &&
                op.data() == endorsement)
                return true;

        return false;
    }

    script_view script_{};
    size_t offset_{};
    bool strip_{ false };
    data_slice endorsement_{};
    bool single_{ false };
    std::span<const data_slice> endorsements_{};
};

} // namespace chain
} // namespace system
} // namespace libbitcoin

#endif
