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
#include "../../test.hpp"

BOOST_AUTO_TEST_SUITE(script_view_tests)

using namespace system::chain;

static void append_push(data_chunk& out, opcode code, size_t size)
{
    out.push_back(static_cast<uint8_t>(code));

    switch (code)
    {
        case opcode::push_one_size:
            out.push_back(possible_narrow_cast<uint8_t>(size));
            break;
        case opcode::push_two_size:
            out.push_back(possible_narrow_cast<uint8_t>(size));
            out.push_back(possible_narrow_cast<uint8_t>(size >> byte_bits));
            break;
        case opcode::push_four_size:
            for (size_t byte{}; byte < sizeof(uint32_t); ++byte)
                out.push_back(possible_narrow_cast<uint8_t>(
                    size >> (byte * byte_bits)));
            break;
        default:
            break;
    }

    for (size_t index{}; index < size; ++index)
        out.push_back(possible_narrow_cast<uint8_t>(index));
}

static void check_matches_script(const data_chunk& encoded)
{
    const script expected{ encoded, false };
    const script_view view{ data_slice{ encoded } };
    auto actual = view.begin();
    size_t offset{};

    BOOST_CHECK_EQUAL(view.data(), data_slice{ encoded });
    BOOST_CHECK_EQUAL(view.size(), encoded.size());
    BOOST_CHECK_EQUAL(view.empty(), encoded.empty());
    BOOST_CHECK_EQUAL(view.is_valid(), expected.is_valid());
    BOOST_CHECK_EQUAL(view.is_roller(), expected.is_roller());
    BOOST_CHECK_EQUAL(view.is_prefail(), expected.is_prefail());
    BOOST_CHECK_EQUAL(view.is_prevalid(), expected.is_prevalid());
    BOOST_CHECK_EQUAL(view.is_underflow(), expected.is_underflow());
    BOOST_CHECK_EQUAL(view.is_oversized(), expected.is_oversized());
    BOOST_CHECK_EQUAL(&view.ops(), &view);

    size_t position{};
    for (const auto& operation: expected.ops())
    {
        BOOST_REQUIRE(actual != view.end());
        const auto raw = operation.to_data();

        BOOST_CHECK(actual->code() == operation.code());
        BOOST_CHECK_EQUAL(actual->data(), data_slice{ operation.data() });
        BOOST_CHECK_EQUAL(actual->raw(), data_slice{ raw });
        BOOST_CHECK_EQUAL(actual->offset(), offset);
        BOOST_CHECK_EQUAL(actual->next_offset(), offset + raw.size());
        BOOST_CHECK_EQUAL(actual->position(), position++);
        BOOST_CHECK_EQUAL(actual->is_underclaimed(),
            operation.is_underclaimed());
        BOOST_CHECK_EQUAL(actual->is_oversized(), operation.is_oversized());
        BOOST_CHECK_EQUAL(actual->is_underflow(), operation.is_underflow());
        BOOST_CHECK_EQUAL(actual->is_conditional(),
            operation.is_conditional());

        if (!actual->raw().empty())
            BOOST_CHECK_EQUAL(actual->raw().data(), encoded.data() + offset);

        offset += raw.size();
        ++actual;
    }

    BOOST_CHECK(actual == view.end());
    BOOST_CHECK_EQUAL(offset, encoded.size());
}

BOOST_AUTO_TEST_CASE(script_view__empty__empty_range)
{
    check_matches_script({});
}

BOOST_AUTO_TEST_CASE(script_view__default__invalid)
{
    BOOST_CHECK(!script_view{}.is_valid());
}

BOOST_AUTO_TEST_CASE(script_view__to_data__prefix_and_body__unchanged)
{
    const auto encoded = base16_chunk("4c03010203ac");
    const script_view instance{ encoded };
    data_chunk prefixed(instance.serialized_size(true));
    stream::out::fast stream{ prefixed };
    write::bytes::fast sink{ stream };

    instance.to_data(sink, true);
    sink.flush();

    auto expected = to_chunk(possible_narrow_cast<uint8_t>(encoded.size()));
    extend(expected, encoded);
    BOOST_CHECK_EQUAL(prefixed, expected);
    BOOST_CHECK_EQUAL(instance.serialized_size(false), encoded.size());
}

BOOST_AUTO_TEST_CASE(script_view__all_opcodes_and_push_sizes__matches_script)
{
    data_chunk encoded{};

    for (uint8_t code{}; code <= static_cast<uint8_t>(opcode::push_size_75);
        ++code)
        append_push(encoded, static_cast<opcode>(code), code);

    append_push(encoded, opcode::push_one_size, max_uint8);
    append_push(encoded, opcode::push_two_size, add1<size_t>(max_uint8));
    append_push(encoded, opcode::push_four_size, 513u);

    for (size_t code = static_cast<uint8_t>(opcode::push_negative_1);
        code <= max_uint8; ++code)
        encoded.push_back(possible_narrow_cast<uint8_t>(code));

    check_matches_script(encoded);
}

BOOST_AUTO_TEST_CASE(script_view__underflows__match_script)
{
    data_stack encodings
    {
        { static_cast<uint8_t>(opcode::push_size_2), 0x42 },
        { static_cast<uint8_t>(opcode::push_one_size) },
        { static_cast<uint8_t>(opcode::push_one_size), 0x02, 0x42 },
        { static_cast<uint8_t>(opcode::push_two_size) },
        { static_cast<uint8_t>(opcode::push_two_size), 0x01 },
        { static_cast<uint8_t>(opcode::push_two_size), 0x02, 0x00, 0x42 },
        { static_cast<uint8_t>(opcode::push_four_size) },
        { static_cast<uint8_t>(opcode::push_four_size), 0x01, 0x00 },
        { static_cast<uint8_t>(opcode::push_four_size), 0x02, 0x00, 0x00,
            0x00, 0x42 },
        { static_cast<uint8_t>(opcode::push_four_size), 0x01, 0x09, 0x3d,
            0x00 }
    };

    for (const auto& encoded: encodings)
        check_matches_script(encoded);
}

BOOST_AUTO_TEST_CASE(script_view__mixed_valid_then_underflow__matches_script)
{
    data_chunk encoded{};
    append_push(encoded, opcode::push_size_3, 3u);
    encoded.push_back(static_cast<uint8_t>(opcode::dup));
    encoded.push_back(static_cast<uint8_t>(opcode::push_two_size));
    encoded.push_back(0x02);
    check_matches_script(encoded);
}

static data_chunk serialize(const script_subview& view)
{
    data_chunk out(view.serialized_size(true));
    stream::out::fast stream{ out };
    write::bytes::fast sink{ stream };
    view.to_data(sink, true);
    sink.flush();
    return out;
}

BOOST_AUTO_TEST_CASE(script_subview__version0__offset_preserves_raw_operations)
{
    const auto encoded = base16_chunk("51ab0201024c02010252ab03030405");
    const script_view script{ encoded };
    const script_subview instance{ script, one };
    const auto expected = base16_chunk("0eab0201024c02010252ab03030405");

    BOOST_CHECK_EQUAL(serialize(instance), expected);
}

BOOST_AUTO_TEST_CASE(script_subview__unversioned__strips_separator_and_nominal_push)
{
    const auto encoded = base16_chunk("51ab0201024c02010252ab03030405");
    const auto endorsement = base16_chunk("0102");
    const script_view script{ encoded };
    const script_subview instance{ script, one, data_slice{ endorsement } };
    const auto expected = base16_chunk("094c0201025203030405");

    BOOST_CHECK_EQUAL(serialize(instance), expected);
}

BOOST_AUTO_TEST_CASE(script_subview__unversioned__strips_multiple_endorsements)
{
    const auto encoded = base16_chunk("020102520303040553");
    const auto first = base16_chunk("0102");
    const auto second = base16_chunk("030405");
    const std::array endorsements
    {
        data_slice{ first },
        data_slice{ second }
    };
    const script_view script{ encoded };
    const script_subview instance{ script, zero, endorsements };

    BOOST_CHECK_EQUAL(serialize(instance), base16_chunk("025253"));
}

BOOST_AUTO_TEST_SUITE_END()
