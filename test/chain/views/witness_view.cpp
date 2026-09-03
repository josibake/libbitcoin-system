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

BOOST_AUTO_TEST_SUITE(witness_view_tests)

using namespace system::chain;

static void check_matches_witness(const data_stack& stack)
{
    const witness expected{ stack };
    const auto encoded = expected.to_data(true);
    const witness_view view{ data_slice{ encoded } };
    auto actual = view.begin();

    BOOST_REQUIRE(view.is_valid());
    BOOST_CHECK_EQUAL(view.data(), data_slice{ encoded });
    BOOST_CHECK_EQUAL(view.size(), encoded.size());
    BOOST_CHECK_EQUAL(view.elements(), stack.size());
    BOOST_CHECK_EQUAL(view.empty(), stack.empty());

    for (const auto& element: stack)
    {
        BOOST_REQUIRE(actual != view.end());
        BOOST_CHECK_EQUAL(*actual, data_slice{ element });

        if (!actual->empty())
        {
            BOOST_CHECK(actual->data() >= encoded.data());
            BOOST_CHECK(actual->data() < encoded.data() + encoded.size());
        }

        ++actual;
    }

    BOOST_CHECK(actual == view.end());
}

BOOST_AUTO_TEST_CASE(witness_view__valid_encodings__match_witness)
{
    check_matches_witness({});
    check_matches_witness({ {}, { 0x42 }, data_chunk(252u, 0x24),
        data_chunk(253u, 0x18), data_chunk(65'536u, 0x81) });
}

BOOST_AUTO_TEST_CASE(witness_view__iterator_copy__is_single_pass_value)
{
    const witness expected{ data_stack{ { 0x42 }, { 0x24 } } };
    const auto encoded = expected.to_data(true);
    const witness_view view{ data_slice{ encoded } };
    auto first = view.begin();
    const auto copy = first++;

    BOOST_REQUIRE(copy != view.end());
    BOOST_REQUIRE(first != view.end());
    BOOST_CHECK_EQUAL(*copy, data_slice{ data_chunk{ 0x42 } });
    BOOST_CHECK_EQUAL(*first, data_slice{ data_chunk{ 0x24 } });
}

BOOST_AUTO_TEST_CASE(witness_view__malformed_encodings__invalid_empty_range)
{
    const data_stack malformed
    {
        {},
        { varint_two_bytes, 0x00, 0x00 },
        { 0x02, 0x01, 0x42 },
        { 0x01, varint_two_bytes, 0x00 },
        { 0x01, 0x02, 0x42 },
        { 0x00, 0x42 },
        { varint_eight_bytes, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff }
    };

    for (const auto& encoded: malformed)
    {
        const witness_view view{ data_slice{ encoded } };
        BOOST_CHECK(!view.is_valid());
        BOOST_CHECK(view.empty());
        BOOST_CHECK(view.begin() == view.end());
    }
}

BOOST_AUTO_TEST_SUITE_END()
