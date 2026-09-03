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
#ifndef LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_CONSTRUCT_IPP
#define LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_CONSTRUCT_IPP

#include <bitcoin/system/chain/chain.hpp>
#include <bitcoin/system/crypto/crypto.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {
namespace machine {

// Constructors.
// ----------------------------------------------------------------------------

// Input script run (default/empty stack).
// 'tx' must remain in scope, this holds state referenced by weak pointers.
// This expectation is guaranteed by the retained tx reference.
TEMPLATE
CLASS::program(const transaction& tx, const input_iterator& input,
    uint32_t active_flags, const chain::signatures& capture) NOEXCEPT
  : source_(tx, input),
    flags_(bit_and(active_flags, bip342_mask)),
    capture_(capture),
    primary_()
{
}

// Legacy p2sh or prevout script run (copied input stack - use first).
// 'other' must remain in scope, this holds state referenced by weak pointers.
// This expectation is guaranteed by the retained source relationship and
// copied program tether (which is not tx state).
TEMPLATE
CLASS::program(const program& other, const script_handle& script) NOEXCEPT
  : source_(other.source_, script),
    flags_(other.flags_),
    capture_(other.capture_),
    primary_(other.primary_)
{
}

// Legacy p2sh or prevout script run (moved input stack/tether - use last).
TEMPLATE
CLASS::program(program&& other, const script_handle& script) NOEXCEPT
  : source_(other.source_, script),
    flags_(other.flags_),
    capture_(other.capture_),
    primary_(std::move(other.primary_))
{
}

// Segwit script run (witness-initialized stack).
// 'tx', 'input' (and iterated chain::input) must remain in scope, as these
// hold chunk state weak references. A witness pointer is explicitly retained
// to guarantee the lifetime of its elements.
TEMPLATE
CLASS::program(const transaction& tx, const input_iterator& input,
    const script_handle& script, uint32_t active_flags,
    script_version version, const witness& witness,
    const chain::signatures& capture) NOEXCEPT
  : source_(tx, input, script, version, witness),
    flags_(bit_and(active_flags, bip342_mask)),
    witness_push_size_(source_.is_witness_push_size()),
    capture_(capture),
    primary_(source_.template initial_stack<Stack>())
{
}

// Taproot script run (witness-initialized stack).
// Same as segwit but with tapleaf, budget, and unstripped bip342 flag.
// Sigop budget is 50 plus size of prefixed serialized witness [bip342].
// Budget is initialized add1(50) to make it zero-based, avoiding signed type.
// This program is never used to construct another, so masked flags_ never mix.
TEMPLATE
CLASS::program(const transaction& tx, const input_iterator& input,
    const script_handle& script, uint32_t active_flags,
    script_version version, const witness& witness,
    const hash_cptr& tapleaf, const chain::signatures& capture) NOEXCEPT
  : source_(tx, input, script, version, witness, tapleaf),
    flags_(active_flags),
    witness_push_size_(source_.is_witness_push_size()),
    capture_(capture),
    primary_(source_.template initial_stack<Stack>()),
    budget_(ceilinged_add(
        add1(chain::signature_cost),
        source_.witness_size()))
{
}

} // namespace machine
} // namespace system
} // namespace libbitcoin

#endif
