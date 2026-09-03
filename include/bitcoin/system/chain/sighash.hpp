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
#ifndef LIBBITCOIN_SYSTEM_CHAIN_SIGHASH_HPP
#define LIBBITCOIN_SYSTEM_CHAIN_SIGHASH_HPP

#include <bitcoin/system/chain/enums/coverage.hpp>
#include <bitcoin/system/chain/enums/extension.hpp>
#include <bitcoin/system/chain/enums/flags.hpp>
#include <bitcoin/system/chain/enums/key_version.hpp>
#include <bitcoin/system/chain/enums/magic_numbers.hpp>
#include <bitcoin/system/chain/enums/script_version.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/hash/hash.hpp>
#include <bitcoin/system/math/math.hpp>
#include <bitcoin/system/stream/stream.hpp>

namespace libbitcoin {
namespace system {
namespace chain {
namespace sighash {

// A Source binds one transaction input and exposes transaction serialization,
// cached aggregate hashes, its prevout, and its annex. Script only requires a
// to_data(writer&, true) overload. This keeps the consensus algorithm shared
// by owning transactions and stable archive views without type erasure.

constexpr coverage mask(uint8_t flags) NOEXCEPT
{
    switch (bit_and<uint8_t>(flags, coverage::mask))
    {
        case coverage::hash_single:
            return coverage::hash_single;
        case coverage::hash_none:
            return coverage::hash_none;
        default:
            return coverage::hash_all;
    }
}

constexpr bool anyone_can_pay(uint8_t flags) NOEXCEPT
{
    return get_right(flags, coverage::anyone_can_pay_bit);
}

inline void write_empty_script(writer& sink) NOEXCEPT
{
    sink.write_byte(zero);
}

inline void write_null_output(writer& sink) NOEXCEPT
{
    sink.write_8_bytes_little_endian(sighash_null_value);
    write_empty_script(sink);
}

template <typename Source, typename Script>
inline void write_inputs(writer& sink, const Source& source,
    const Script& script, uint8_t flags, bool preserve_sequences) NOEXCEPT
{
    const auto selected = source.input_index();
    const auto anyone = anyone_can_pay(flags);
    sink.write_variable(anyone ? one : source.inputs());

    if (anyone)
    {
        source.write_point(sink, selected);
        script.to_data(sink, true);
        sink.write_4_bytes_little_endian(source.sequence(selected));
        return;
    }

    for (size_t input{}; input < source.inputs(); ++input)
    {
        source.write_point(sink, input);
        if (input == selected)
            script.to_data(sink, true);
        else
            write_empty_script(sink);

        sink.write_4_bytes_little_endian(
            preserve_sequences || input == selected ?
                source.sequence(input) : zero);
    }
}

template <typename Source>
inline void write_outputs(writer& sink, const Source& source,
    coverage mode) NOEXCEPT
{
    const auto selected = source.input_index();

    switch (mode)
    {
        case coverage::hash_single:
            sink.write_variable(add1(selected));
            for (size_t output{}; output < selected; ++output)
                write_null_output(sink);

            source.write_output(sink, selected);
            return;
        case coverage::hash_none:
            sink.write_variable(zero);
            return;
        default:
        case coverage::hash_all:
            sink.write_variable(source.outputs());
            for (size_t output{}; output < source.outputs(); ++output)
                source.write_output(sink, output);
    }
}

template <typename Source, typename Script>
inline void unversioned(hash_digest& out, const Source& source,
    const Script& script, uint8_t flags) NOEXCEPT
{
    const auto mode = mask(flags);
    if (mode == coverage::hash_single &&
        source.input_index() >= source.outputs())
    {
        out = one_hash;
        return;
    }

    stream::out::fast stream{ out };
    hash::sha256x2::fast sink{ stream };
    sink.write_4_bytes_little_endian(source.version());
    write_inputs(sink, source, script, flags, mode == coverage::hash_all);
    write_outputs(sink, source, mode);
    sink.write_4_bytes_little_endian(source.locktime());

    // CONSENSUS: the one-byte flag is encoded as four bytes in the preimage.
    sink.write_4_bytes_little_endian(flags);
    sink.flush();
}

template <typename Source, typename Script>
inline void version0(hash_digest& out, const Source& source,
    const Script& script, uint64_t value, uint8_t flags) NOEXCEPT
{
    const auto mode = mask(flags);
    const auto anyone = anyone_can_pay(flags);
    const auto single = mode == coverage::hash_single;
    const auto all = mode == coverage::hash_all;
    const auto input = source.input_index();

    stream::out::fast stream{ out };
    hash::sha256x2::fast sink{ stream };
    sink.write_4_bytes_little_endian(source.version());
    sink.write_bytes(!anyone ? source.double_hash_points() : null_hash);
    sink.write_bytes(!anyone && all ?
        source.double_hash_sequences() : null_hash);
    source.write_point(sink, input);
    script.to_data(sink, true);
    sink.write_8_bytes_little_endian(value);
    sink.write_4_bytes_little_endian(source.sequence(input));
    sink.write_bytes(single && input < source.outputs() ?
        source.double_hash_output(input) :
        (all ? source.double_hash_outputs() : null_hash));
    sink.write_4_bytes_little_endian(source.locktime());

    // CONSENSUS: the one-byte flag is encoded as four bytes in the preimage.
    sink.write_4_bytes_little_endian(flags);
    sink.flush();
}

template <typename Source>
inline bool version1(hash_digest& out, const Source& source, uint64_t value,
    const hash_cptr& tapleaf, uint8_t flags, uint32_t separator) NOEXCEPT
{
    constexpr uint8_t epoch{};
    const auto mode = mask(flags);
    const auto anyone = anyone_can_pay(flags);
    const auto single = mode == coverage::hash_single;
    const auto all = mode == coverage::hash_all;
    const auto input = source.input_index();
    const auto annex = source.has_annex();

    // CONSENSUS: public callers may omit prevout population.
    if (anyone && !source.has_prevout())
        return false;

    // CONSENSUS: taproot eliminates the historical one_hash result.
    if (single && input >= source.outputs())
        return false;

    stream::out::fast stream{ out };
    hash::sha256t::fast<"TapSighash"> sink{ stream };
    sink.write_byte(epoch);
    sink.write_byte(flags);
    sink.write_4_bytes_little_endian(source.version());
    sink.write_4_bytes_little_endian(source.locktime());

    if (!anyone)
    {
        sink.write_bytes(source.single_hash_points());
        sink.write_bytes(source.single_hash_amounts());
        sink.write_bytes(source.single_hash_scripts());
        sink.write_bytes(source.single_hash_sequences());
    }

    if (all)
        sink.write_bytes(source.single_hash_outputs());

    const auto tapscript = !is_null(tapleaf);
    const auto extension = to_value(tapscript ?
        chain::extension::tapscript : chain::extension::taproot);
    sink.write_byte(set_right(shift_left(extension), zero, annex));

    if (anyone)
    {
        source.write_point(sink, input);
        sink.write_8_bytes_little_endian(value);
        source.write_prevout_script(sink);
        sink.write_4_bytes_little_endian(source.sequence(input));
    }
    else
    {
        sink.write_4_bytes_little_endian(input);
    }

    if (annex)
        sink.write_bytes(source.annex_hash());

    if (single)
        sink.write_bytes(source.single_hash_output(input));

    if (tapscript)
    {
        sink.write_bytes(*tapleaf);
        sink.write_byte(to_value(key_version::tapscript));
        sink.write_4_bytes_little_endian(separator);
    }

    sink.flush();
    return true;
}

template <typename Source, typename Script>
inline bool generate(hash_digest& out, const Source& source,
    const Script& script, uint64_t value, const hash_cptr& tapleaf,
    script_version version, uint8_t flags, uint32_t active_flags,
    uint32_t separator=default_separators) NOEXCEPT
{
    BC_ASSERT(!source.is_coinbase());
    const auto bip143 = to_bool(active_flags & chain::flags::bip143_rule);
    const auto bip342 = to_bool(active_flags & chain::flags::bip342_rule);

    if (bip143 && version == script_version::segwit)
    {
        version0(out, source, script, value, flags);
        return true;
    }

    if (bip342 && version == script_version::taproot)
        return version1(out, source, value, tapleaf, flags, separator);

    unversioned(out, source, script, flags);
    return true;
}

} // namespace sighash
} // namespace chain
} // namespace system
} // namespace libbitcoin

#endif
