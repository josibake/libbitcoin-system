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

BOOST_AUTO_TEST_SUITE(secp256k1_tests)

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_verify__slice__expected)
{
    using namespace system::schnorr;

    constexpr ec_secret secret = base16_array(
        "0000000000000000000000000000000000000000000000000000000000000003");
    constexpr hash_digest message{};
    constexpr hash_digest auxiliary{};

    ec_compressed point{};
    ec_signature signature{};
    BOOST_REQUIRE(secret_to_public(point, secret));
    BOOST_REQUIRE(sign(signature, secret, message, auxiliary));

    const data_slice x_point{ std::next(point.begin()), point.end() };
    BOOST_REQUIRE(verify_signature(x_point, message, signature));
}

BOOST_AUTO_TEST_SUITE_END()
