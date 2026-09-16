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
#include <bitcoin/system/chain/taproot.hpp>

#include <bitcoin/system/chain/annex.hpp>
#include <bitcoin/system/chain/script.hpp>
#include <bitcoin/system/chain/tapscript.hpp>
#include <bitcoin/system/chain/views/script_view.hpp>
#include <bitcoin/system/crypto/crypto.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/hash/hash.hpp>
#include <bitcoin/system/stream/stream.hpp>

namespace libbitcoin {
namespace system {
namespace chain {

template <typename Script>
static hash_digest leaf_hash(uint8_t version, const Script& script) NOEXCEPT
{
    hash_digest out{};
    stream::out::fast stream{ out };
    hash::sha256t::fast<"TapLeaf"> sink{ stream };
    sink.write_byte(version);
    script.to_data(sink, true);
    sink.flush();
    return out;
}

// protected
// ----------------------------------------------------------------------------

hash_digest taproot::merkle_root(const tapscript::keys_t& keys, size_t count,
    const hash_digest& tapleaf_hash) NOEXCEPT
{
    hash_digest hash{ tapleaf_hash };
    for (size_t key{}; key < count; ++key)
        hash = sorted_branch_hash(hash, keys.at(key));

    return hash;
}

hash_digest taproot::sorted_branch_hash(const hash_digest& left,
    const hash_digest& right) NOEXCEPT
{
    return std::lexicographical_compare(left.begin(), left.end(),
        right.begin(), right.end()) ? branch_hash(left, right) :
        branch_hash(right, left);
}

// TapBranch
hash_digest taproot::branch_hash(const hash_digest& first,
    const hash_digest& second) NOEXCEPT
{
    hash_digest out{};
    stream::out::fast stream{ out };
    hash::sha256t::fast<"TapBranch"> sink{ stream };
    sink.write_bytes(first);
    sink.write_bytes(second);
    sink.flush();
    return out;
}

// TapTweak
hash_digest taproot::tweak_hash(const ec_xonly& key,
    const hash_digest& merkle) NOEXCEPT
{
    hash_digest out{};
    stream::out::fast stream{ out };
    hash::sha256t::fast<"TapTweak"> sink{ stream };
    sink.write_bytes(key);
    sink.write_bytes(merkle);
    sink.flush();
    return out;
}

// public
// ----------------------------------------------------------------------------

// TapLeaf
hash_digest taproot::leaf_hash(uint8_t version,
    const script& script) NOEXCEPT
{
    return chain::leaf_hash(version, script);
}

hash_digest taproot::leaf_hash(uint8_t version,
    const script_view& script) NOEXCEPT
{
    return chain::leaf_hash(version, script);
}

// static
bool taproot::drop_annex(chunk_cptrs& stack) NOEXCEPT
{
    if (!annex::is_annex_pattern(stack))
        return false;

    stack.pop_back();
    return true;
}

hash_digest taproot::commitment_tweak(const tapscript& control,
    const hash_digest& leaf) NOEXCEPT
{
    return commitment_tweak(control.data(), leaf);
}

hash_digest taproot::commitment_tweak(const data_slice& control,
    const hash_digest& leaf) NOEXCEPT
{
    BC_ASSERT(tapscript::is_control(control));

    constexpr auto key_begin = one;
    constexpr auto path_begin = add1(ec_xonly_size);
    const auto& key = unsafe_array_cast<uint8_t, ec_xonly_size>(
        std::next(control.begin(), key_begin));

    auto root = leaf;
    for (auto path = std::next(control.begin(), path_begin);
        path != control.end(); std::advance(path, ec_xonly_size))
        root = sorted_branch_hash(root,
            unsafe_array_cast<uint8_t, ec_xonly_size>(path));

    return tweak_hash(key, root);
}

bool taproot::verify_commit(const tapscript& control, const ec_xonly& out_key,
    const hash_digest& leaf) NOEXCEPT
{
    return verify_commit(control.data(), out_key, leaf);
}

bool taproot::verify_commit(const data_slice& control, const ec_xonly& out_key,
    const hash_digest& leaf) NOEXCEPT
{
    if (!tapscript::is_control(control))
        return false;

    constexpr auto key_begin = one;
    const auto& key = unsafe_array_cast<uint8_t, ec_xonly_size>(
        std::next(control.begin(), key_begin));
    const auto tweak = commitment_tweak(control, leaf);
    constexpr auto parity_mask = bit_not(tapscript_mask);
    const auto parity = to_bool(bit_and(control.front(), parity_mask));
    return schnorr::verify_commitment(key, tweak, out_key, parity);
}

} // namespace chain
} // namespace system
} // namespace libbitcoin
