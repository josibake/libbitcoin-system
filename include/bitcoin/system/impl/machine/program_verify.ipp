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
#ifndef LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_VERIFY_IPP
#define LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_VERIFY_IPP

#include <iterator>
#include <span>
#include <bitcoin/system/chain/chain.hpp>
#include <bitcoin/system/crypto/crypto.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {
namespace machine {

// Endorsement parsing.
// ----------------------------------------------------------------------------

// static/private
// BIP341: Using any undefined hash_type causes validation failure if violated.
// defined types: 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, or 0x83. [zero is the
// default and cannot be explicit, but is serialized for signature hashing].
TEMPLATE
inline bool CLASS::
is_schnorr_sighash(uint8_t sighash_flags) NOEXCEPT
{
    using namespace chain;

    switch (sighash_flags)
    {
        // BIP341: zero is invalid sighash, must be explicit to prevent mally.
        ////case coverage::hash_default:
        case coverage::hash_all:
        case coverage::hash_none:
        case coverage::hash_single:
        case coverage::all_anyone_can_pay:
        case coverage::none_anyone_can_pay:
        case coverage::single_anyone_can_pay:
            return true;
        default:
            return false;
    }
}

TEMPLATE
INLINE const ec_signature& CLASS::
schnorr_split(uint8_t& sighash_flags,
    const data_slice& endorsement) const NOEXCEPT
{
    using namespace chain;
    using namespace schnorr;

    sighash_flags = coverage::invalid;
    const auto size = endorsement.size();

    if (size == ec_signature_size)
    {
        // BIP341: if [sighash byte] is omitted the resulting signatures are 64
        // bytes, and [default == 0] mode is implied (implies SIGHASH_ALL).
        sighash_flags = coverage::hash_default;
    }
    else if (size == add1(ec_signature_size))
    {
        // BIP341: signature has sighash byte appended in the usual fashion.
        const auto byte = endorsement.back();

        // BIP341: Defined sighash type required (otherwise invalid is set).
        if (is_schnorr_sighash(byte))
            sighash_flags = byte;
    }
    else
    {
        // This makes an invalid return safe to dereference, and may be
        // compiled out unless a caller does in fact access it.
        static constexpr ec_signature empty{};
        return empty;
    }

    return unsafe_array_cast<uint8_t, ec_signature_size>(endorsement.data());
}

TEMPLATE
INLINE data_slice CLASS::
ecdsa_split(uint8_t& sighash_flags,
    const data_slice& endorsement) const NOEXCEPT
{
    BC_ASSERT(!endorsement.empty());
    sighash_flags = endorsement.back();

    // data_slice is returned since the size of the DER encoding is not fixed.
    return { endorsement.begin(), std::prev(endorsement.end()) };
}

TEMPLATE
INLINE bool CLASS::
decode_signature(ec_signature& out, const data_slice& der_signature,
    bool strict) const NOEXCEPT
{
    return ecdsa::decode_signature(out, der_signature, strict);
}

// Signature subscripting.
// ----------------------------------------------------------------------------

TEMPLATE
INLINE void CLASS::
set_subscript(size_t position) NOEXCEPT
{
    source_.set_subscript(position);

    // The subscript is changed, so any cached signature hash is stale.
    uncache();
}

// Signature hashing.
// ----------------------------------------------------------------------------

TEMPLATE
INLINE bool CLASS::
signature_hash(hash_digest& out, uint8_t sighash_flags) const NOEXCEPT
{
    return source_.signature_hash(out, sighash_flags, flags_);
}

TEMPLATE
INLINE bool CLASS::
signature_hash(hash_digest& out, const data_slice& endorsement,
    uint8_t sighash_flags) const NOEXCEPT
{
    return source_.signature_hash(out, endorsement, sighash_flags, flags_);
}

TEMPLATE
INLINE bool CLASS::
signature_hash(hash_digest& out, std::span<const data_slice> endorsements,
    uint8_t sighash_flags) const NOEXCEPT
{
    return source_.signature_hash(out, endorsements, sighash_flags, flags_);
}

// Multisig signature hash caching.
// ----------------------------------------------------------------------------

// ****************************************************************************
// CONSENSUS: The cache is keyed only on sighash flags, so it is valid only
// while the subscript is unchanged. A v1 signature hash commits to the
// op_codeseparator position and a v0 subscript is stripped of the endorsements
// of the op that created it, so both invalidate the cache.
// ****************************************************************************
TEMPLATE
INLINE bool CLASS::
cached(uint8_t sighash_flags) const NOEXCEPT
{
    return multisig_.set && (multisig_.flags == sighash_flags);
}

TEMPLATE
INLINE void CLASS::
uncache() const NOEXCEPT
{
    multisig_.set = false;
}

TEMPLATE
INLINE bool CLASS::
set_hash(uint8_t sighash_flags) const NOEXCEPT
{
    // This v1 (unsubscripted) sighash can fail, in which case don't set cache.
    return ((multisig_.set = signature_hash(multisig_.hash,
        multisig_.flags = sighash_flags)));
}

TEMPLATE
INLINE void CLASS::
set_hash(std::span<const data_slice> endorsements,
    uint8_t sighash_flags) const NOEXCEPT
{
    // Only v1 (unsubscripted) sighash can fail, so void return here.
    signature_hash(multisig_.hash, endorsements,
        multisig_.flags = sighash_flags);
    multisig_.set = true;
}

TEMPLATE
INLINE const hash_digest& CLASS::
cached_hash() const NOEXCEPT
{
    BC_ASSERT(multisig_.set);
    return multisig_.hash;
}

} // namespace machine
} // namespace system
} // namespace libbitcoin

#endif
