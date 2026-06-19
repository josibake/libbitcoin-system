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
#include <bitcoin/system/wallet/addresses/silent_payment.hpp>

#include <algorithm>
#include <cstdlib>
#include <iterator>
#include <utility>
#include <bitcoin/system/chain/enums/script_pattern.hpp>
#include <bitcoin/system/chain/enums/script_version.hpp>
#include <bitcoin/system/chain/input.hpp>
#include <bitcoin/system/chain/operation.hpp>
#include <bitcoin/system/chain/output.hpp>
#include <bitcoin/system/chain/point.hpp>
#include <bitcoin/system/chain/script.hpp>
#include <bitcoin/system/chain/tapscript.hpp>
#include <bitcoin/system/chain/transaction.hpp>
#include <bitcoin/system/crypto/secp256k1.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/endian/endian.hpp>
#include <bitcoin/system/hash/hash.hpp>
#include <bitcoin/system/have.hpp>
#include <bitcoin/system/radix/base_16.hpp>
#include <bitcoin/system/stream/stream.hpp>

#if !defined(HAVE_ULTRAFAST)
    #error "Silent payment prefix scanning requires UltrafastSecp256k1."
#endif

#include <ufsecp_libbitcoin.h>

namespace libbitcoin {
namespace system {
namespace wallet {

BC_PUSH_WARNING(NO_THROW_IN_NOEXCEPT)

static constexpr auto bip341_nums_key = base16_array(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

bool silent_payment::copy_xonly(ec_xonly& out, const data_chunk& value) NOEXCEPT
{
    if (value.size() != ec_xonly_size)
        return false;

    std::copy_n(value.begin(), ec_xonly_size, out.begin());
    return true;
}

bool silent_payment::copy_compressed(ec_compressed& out,
    const data_chunk& value) NOEXCEPT
{
    if (!is_compressed_key(value))
        return false;

    std::copy_n(value.begin(), ec_compressed_size, out.begin());
    return true;
}

bool silent_payment::contains_prefix(const output_prefixes& prefixes,
    output_prefix value) NOEXCEPT
{
    return std::find(prefixes.begin(), prefixes.end(), value) != prefixes.end();
}

bool silent_payment::extract_last_witness_key(ec_compressed& out,
    const chain::input& in) NOEXCEPT
{
    const auto& stack = in.witness().stack();
    if (stack.empty() || !stack.back())
        return false;

    return copy_compressed(out, *stack.back());
}

bool silent_payment::extract_p2pkh_key(ec_compressed& out,
    const chain::input& in) NOEXCEPT
{
    if (!in.prevout)
        return false;

    const auto& ops = in.prevout->script().ops();
    if (!chain::script::is_pay_key_hash_pattern(ops))
        return false;

    const auto bytes = in.script().to_data(false);
    if (bytes.size() < ec_compressed_size)
        return false;

    // P2PKH input scripts are malleable, so scan backward for the compressed
    // key whose HASH160 matches the spent output rather than trusting the last
    // push.
    for (auto offset = bytes.size() - ec_compressed_size + one; offset > zero;
        --offset)
    {
        const auto start = std::next(bytes.begin(), offset - one);
        if (!is_compressed_key_sign(*start))
            continue;

        ec_compressed key{};
        std::copy_n(start, ec_compressed_size, key.begin());
        const auto digest = bitcoin_short_hash(key);
        const auto& hash = unsafe_array_cast<uint8_t, short_hash_size>(
            ops.at(2).data().data());
        if (digest == hash)
        {
            out = key;
            return true;
        }
    }

    return false;
}

bool silent_payment::to_even_compressed(ec_compressed& out,
    const ec_xonly& point) NOEXCEPT
{
    out.front() = ec_even_sign;
    std::copy(point.begin(), point.end(), std::next(out.begin()));
    return verify_point(out);
}

bool silent_payment::is_nums_internal_key(const chain::input& in) NOEXCEPT
{
    const auto& stack = in.witness().stack();

    // BIP352 only skips taproot script-path spends whose control block internal
    // key is the BIP341 NUMS point H.
    if (stack.size() <= one)
        return false;

    const auto control = in.witness().annex() ?
        *std::prev(stack.end(), 2) : stack.back();
    if (!control)
        return false;

    const chain::tapscript script{ control };
    return script.is_valid()
        && script.key() == bip341_nums_key;
}

bool silent_payment::extract_taproot_key(ec_compressed& out,
    const chain::input& in) NOEXCEPT
{
    if (!in.prevout)
        return false;

    if (is_nums_internal_key(in))
        return false;

    const auto& program = in.prevout->script().witness_program();
    if (!program || program->size() != ec_xonly_size)
        return false;

    ec_xonly xonly{};
    if (!copy_xonly(xonly, *program))
        return false;

    return to_even_compressed(out, xonly);
}

bool silent_payment::extract_scan_output(scan_output& out,
    const chain::output& output) NOEXCEPT
{
    if (!chain::script::is_pay_witness_taproot_pattern(output.script().ops()))
        return false;

    const auto& program = output.script().witness_program();
    if (!program || !copy_xonly(out.key, *program))
        return false;

    return true;
}

bool silent_payment::extract_scan_outputs(scan_outputs& out,
    const chain::transaction& tx) NOEXCEPT
{
    const auto& outputs = *tx.outputs_ptr();
    out.reserve(outputs.size());

    for (const auto& output: outputs)
    {
        scan_output entry{};
        if (extract_scan_output(entry, *output))
            out.push_back(entry);
    }

    return !out.empty();
}

bool silent_payment::has_scan_outputs(const chain::transaction& tx) NOEXCEPT
{
    const auto& outputs = *tx.outputs_ptr();
    return std::any_of(outputs.begin(), outputs.end(),
        [](const auto& output) NOEXCEPT
        {
            scan_output entry{};
            return extract_scan_output(entry, *output);
        });
}

silent_payment::output_prefix silent_payment::to_output_prefix(
    const ec_xonly& key) NOEXCEPT
{
    return from_big<output_prefix, zero>(key);
}

bool silent_payment::label_tweak(ec_secret& out, const ec_secret& scan_secret,
    uint32_t label) NOEXCEPT
{
    stream::out::fast stream{ out };
    hash::sha256t::fast<"BIP0352/Label"> sink{ stream };
    sink.write_bytes(scan_secret);
    sink.write_4_bytes_big_endian(label);
    sink.flush();
    return verify_secret(out);
}

bool silent_payment::to_scan_prefix(output_prefix& out,
    const ec_secret& scan_secret, const ec_compressed& prevouts_summary,
    const ec_compressed& spend_public) NOEXCEPT
{
    static thread_local ufsecp::lbtc::Controller context{ UFSECP_LBTC_AUTO };
    if (!context.ok()) std::abort();

    return ufsecp_lbtc_sp_scan(context.get(), scan_secret.data(),
        spend_public.data(), prevouts_summary.data(), one, &out) == UFSECP_OK;
}

bool silent_payment::is_excluded_segwit_future(
    const chain::input& in) NOEXCEPT
{
    return in.prevout
        && in.prevout->script().version() == chain::script_version::reserved;
}

bool silent_payment::extract_shared_secret_key(ec_compressed& out,
    const chain::input& in) NOEXCEPT
{
    if (!in.prevout)
        return false;

    switch (in.prevout->script().output_pattern())
    {
        case chain::script_pattern::pay_witness_v1_taproot:
            return extract_taproot_key(out, in);
        case chain::script_pattern::pay_witness_key_hash:
            return extract_last_witness_key(out, in);
        case chain::script_pattern::pay_script_hash:
            return chain::script::is_sign_witness_key_hash_pattern(
                in.script().ops())
                && extract_last_witness_key(out, in);
        case chain::script_pattern::pay_key_hash:
            return extract_p2pkh_key(out, in);
        default:
            return false;
    }
}

bool silent_payment::outpoint_serialized_less(const chain::point& left,
    const chain::point& right) NOEXCEPT
{
    if (left.hash() != right.hash())
        return std::lexicographical_compare(left.hash().begin(),
            left.hash().end(), right.hash().begin(), right.hash().end());

    const auto left_index = to_little_endian(left.index());
    const auto right_index = to_little_endian(right.index());
    return std::lexicographical_compare(left_index.begin(), left_index.end(),
        right_index.begin(), right_index.end());
}

bool silent_payment::compute_input_hash(ec_secret& out,
    const chain::transaction& tx,
    const ec_compressed& sum) NOEXCEPT
{
    const auto& inputs = *tx.inputs_ptr();
    if (inputs.empty())
        return false;

    // BIP352 orders by serialized outpoints, not point's uniqueness ordering.
    const auto by_serialized_outpoint =
        [](const auto& left, const auto& right) NOEXCEPT
    {
        return silent_payment::outpoint_serialized_less(left->point(),
            right->point());
    };

    const auto minimum = std::min_element(inputs.begin(), inputs.end(),
        by_serialized_outpoint);
    if (minimum == inputs.end())
        return false;

    stream::out::fast stream{ out };
    hash::sha256t::fast<"BIP0352/Inputs"> sink{ stream };
    (*minimum)->point().to_data(sink);
    sink.write_bytes(sum);
    sink.flush();

    return verify_secret(out);
}

bool silent_payment::compute_scan_record(scan_record& out,
    const chain::transaction& tx) NOEXCEPT
{
    out = {};
    scan_outputs outputs{};
    if (tx.is_coinbase() || !extract_scan_outputs(outputs, tx))
        return false;

    const auto& inputs = *tx.inputs_ptr();
    ec_compresseds keys{};
    keys.reserve(inputs.size());

    for (const auto& in: inputs)
    {
        if (!in->prevout || is_excluded_segwit_future(*in))
        {
            out = {};
            return false;
        }

        ec_compressed key{};
        if (extract_shared_secret_key(key, *in))
            keys.push_back(key);
    }

    ec_compressed sum{};
    ec_secret input_hash{};
    if (keys.empty() || !ec_sum(sum, keys) ||
        !compute_input_hash(input_hash, tx, sum))
    {
        out = {};
        return false;
    }

    out.prevouts_summary = sum;
    if (!ec_multiply(out.prevouts_summary, input_hash))
    {
        out = {};
        return false;
    }

    out.prefixes.reserve(outputs.size());
    for (const auto& output: outputs)
        out.prefixes.push_back(to_output_prefix(output.key));

    return true;
}

silent_payment::silent_payment(const ec_secret& scan_secret,
    const ec_compressed& spend_public, const std_vector<uint32_t>& values)
    NOEXCEPT
  : scan_secret_(scan_secret)
{
    auto labels = values;
    labels.push_back(zero);
    std::sort(labels.begin(), labels.end());
    labels.erase(std::unique(labels.begin(), labels.end()), labels.end());

    ec_uncompressed spend_point{};
    if (!verify_secret(scan_secret_) || !decompress(spend_point, spend_public))
        return;

    spend_publics_.reserve(add1(labels.size()));
    spend_publics_.push_back(spend_public);

    for (const auto label: labels)
    {
        ec_secret tweak{};
        ec_uncompressed point{ spend_point };
        ec_compressed compressed{};
        if (!label_tweak(tweak, scan_secret_, label) ||
            !ec_add(point, tweak) || !compress(compressed, point))
        {
            return;
        }

        spend_publics_.push_back(compressed);
    }

    valid_ = true;
}

silent_payment::operator bool() const NOEXCEPT
{
    return valid();
}

bool silent_payment::valid() const NOEXCEPT
{
    return valid_ && !spend_publics_.empty();
}

bool silent_payment::match_prefixes(bool& out,
    const ec_compressed& prevouts_summary,
    const output_prefixes& prefixes) const NOEXCEPT
{
    out = false;

    if (!valid())
        return false;

    if (!verify_point(prevouts_summary))
        return false;

    if (prefixes.empty())
        return true;

    for (const auto& spend_public: spend_publics_)
    {
        output_prefix prefix{};
        if (!to_scan_prefix(prefix, scan_secret_, prevouts_summary,
            spend_public))
        {
            return false;
        }

        if (contains_prefix(prefixes, prefix))
        {
            out = true;
            return true;
        }
    }

    return true;
}

BC_POP_WARNING()

} // namespace wallet
} // namespace system
} // namespace libbitcoin
