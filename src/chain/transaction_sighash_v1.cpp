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
#include <bitcoin/system/chain/transaction.hpp>

#include <bitcoin/system/chain/enums/opcode.hpp>
#include <bitcoin/system/chain/enums/coverage.hpp>
#include <bitcoin/system/chain/enums/extension.hpp>
#include <bitcoin/system/chain/enums/key_version.hpp>
#include <bitcoin/system/chain/enums/magic_numbers.hpp>
#include <bitcoin/system/chain/input.hpp>
#include <bitcoin/system/chain/output.hpp>
#include <bitcoin/system/chain/script.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {
namespace chain {

// Signature hash source (version 1 - taproot).
// ----------------------------------------------------------------------------

// static
// Zero-based opcode position of the last executed op_codeseparator before
// currently executed signature opcode (0xffffffff if none) [bip342]. Previous
// versions require the next opcode, but this requires the position. Since the
// op_codeseparator implementation sets offset to next, it must be decremented.
uint32_t transaction::subscript_v1(const script& script) NOEXCEPT
{
    if (script.ops().empty())
        return chain::default_separators;

    const auto next = std::distance(script.ops().begin(), script.offset);
    return is_zero(next) ? chain::default_separators :
        possible_narrow_and_sign_cast<uint32_t>(sub1(next));
}

const hash_digest&
transaction::sighash_source::single_hash_points() const NOEXCEPT
{
    return tx_.single_hash_points();
}

const hash_digest&
transaction::sighash_source::single_hash_amounts() const NOEXCEPT
{
    return tx_.single_hash_amounts();
}

const hash_digest&
transaction::sighash_source::single_hash_scripts() const NOEXCEPT
{
    return tx_.single_hash_scripts();
}

const hash_digest&
transaction::sighash_source::single_hash_sequences() const NOEXCEPT
{
    return tx_.single_hash_sequences();
}

const hash_digest&
transaction::sighash_source::single_hash_outputs() const NOEXCEPT
{
    return tx_.single_hash_outputs();
}

const hash_digest& transaction::sighash_source::single_hash_output(
    size_t output) const NOEXCEPT
{
    return tx_.outputs_->at(output)->get_hash();
}

} // namespace chain
} // namespace system
} // namespace libbitcoin
