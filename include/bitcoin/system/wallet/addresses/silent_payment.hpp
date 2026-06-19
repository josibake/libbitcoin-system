/**
 * Copyright (c) 2011-2026 libbitcoin developers (see AUTHORS)
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
#ifndef LIBBITCOIN_SYSTEM_WALLET_ADDRESSES_SILENT_PAYMENT_HPP
#define LIBBITCOIN_SYSTEM_WALLET_ADDRESSES_SILENT_PAYMENT_HPP

#include <bitcoin/system/crypto/secp256k1.hpp>
#include <bitcoin/system/define.hpp>

namespace libbitcoin {
namespace system {
namespace chain {

class input;
class output;
class point;
class transaction;

} // namespace chain
namespace wallet {

class BC_API silent_payment
{
public:
    /// The first eight x-only output key bytes as a big-endian integer.
    typedef uint64_t output_prefix;
    typedef std_vector<output_prefix> output_prefixes;

    static constexpr size_t output_prefix_size = sizeof(output_prefix);

    struct scan_record
    {
        ec_compressed prevouts_summary{};
        output_prefixes prefixes{};
    };

    DEFAULT_COPY_MOVE_DESTRUCT(silent_payment);

    /// The change label (0) is always scanned.
    silent_payment(const ec_secret& scan_secret, const ec_compressed& spend_public,
        const std_vector<uint32_t>& labels) NOEXCEPT;

    operator bool() const NOEXCEPT;

    static bool compute_scan_record(scan_record& out,
        const chain::transaction& tx) NOEXCEPT;
    static bool has_scan_outputs(const chain::transaction& tx) NOEXCEPT;
    static output_prefix to_output_prefix(const ec_xonly& key) NOEXCEPT;

    /// Match 64-bit output prefixes from one transaction as a discovery filter.
    /// True results identify candidate transactions for wallet-side matching.
    bool match_prefixes(bool& out, const ec_compressed& prevouts_summary,
        const output_prefixes& prefixes) const NOEXCEPT;

protected:
    struct scan_output
    {
        ec_xonly key{};
    };

    typedef std_vector<scan_output> scan_outputs;

    static bool copy_xonly(ec_xonly& out, const data_chunk& value) NOEXCEPT;
    static bool copy_compressed(ec_compressed& out,
        const data_chunk& value) NOEXCEPT;
    static bool contains_prefix(const output_prefixes& prefixes,
        output_prefix value) NOEXCEPT;
    static bool extract_last_witness_key(ec_compressed& out,
        const chain::input& in) NOEXCEPT;
    static bool extract_p2pkh_key(ec_compressed& out,
        const chain::input& in) NOEXCEPT;
    static bool to_even_compressed(ec_compressed& out,
        const ec_xonly& point) NOEXCEPT;
    static bool is_nums_internal_key(const chain::input& in) NOEXCEPT;
    static bool extract_taproot_key(ec_compressed& out,
        const chain::input& in) NOEXCEPT;
    static bool extract_scan_output(scan_output& out,
        const chain::output& output) NOEXCEPT;
    static bool extract_scan_outputs(scan_outputs& out,
        const chain::transaction& tx) NOEXCEPT;
    static bool label_tweak(ec_secret& out, const ec_secret& scan_secret,
        uint32_t label) NOEXCEPT;
    static bool is_excluded_segwit_future(const chain::input& in) NOEXCEPT;
    static bool extract_shared_secret_key(ec_compressed& out,
        const chain::input& in) NOEXCEPT;
    static bool outpoint_serialized_less(const chain::point& left,
        const chain::point& right) NOEXCEPT;
    static bool compute_input_hash(ec_secret& out,
        const chain::transaction& tx, const ec_compressed& sum) NOEXCEPT;

    bool valid() const NOEXCEPT;

private:
    static bool to_scan_prefix(output_prefix& out, const ec_secret& scan_secret,
        const ec_compressed& prevouts_summary,
        const ec_compressed& spend_public) NOEXCEPT;

    ec_secret scan_secret_{};
    ec_compresseds spend_publics_{};
    bool valid_{};
};

} // namespace wallet
} // namespace system
} // namespace libbitcoin

#endif
