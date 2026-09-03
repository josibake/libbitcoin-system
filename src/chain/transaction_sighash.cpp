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

#include <bitcoin/system/chain/enums/coverage.hpp>
#include <bitcoin/system/chain/input.hpp>
#include <bitcoin/system/chain/output.hpp>
#include <bitcoin/system/chain/script.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/stream/stream.hpp>

namespace libbitcoin {
namespace system {
namespace chain {

// Signature hash source (common).
// ----------------------------------------------------------------------------

transaction::sighash_source::sighash_source(const transaction& tx,
    const input_iterator& input) NOEXCEPT
  : tx_(tx), input_(input), index_(tx.input_index(input))
{
}

bool transaction::sighash_source::is_coinbase() const NOEXCEPT
{
    return tx_.is_coinbase();
}

size_t transaction::sighash_source::inputs() const NOEXCEPT
{
    return tx_.inputs_->size();
}

size_t transaction::sighash_source::outputs() const NOEXCEPT
{
    return tx_.outputs_->size();
}

uint32_t transaction::sighash_source::version() const NOEXCEPT
{
    return tx_.version_;
}

uint32_t transaction::sighash_source::locktime() const NOEXCEPT
{
    return tx_.locktime_;
}

uint32_t transaction::sighash_source::input_index() const NOEXCEPT
{
    return index_;
}

uint32_t transaction::sighash_source::sequence(size_t input) const NOEXCEPT
{
    return tx_.inputs_->at(input)->sequence();
}

void transaction::sighash_source::write_point(writer& sink,
    size_t input) const NOEXCEPT
{
    tx_.inputs_->at(input)->point().to_data(sink);
}

void transaction::sighash_source::write_output(writer& sink,
    size_t output) const NOEXCEPT
{
    tx_.outputs_->at(output)->to_data(sink);
}

bool transaction::sighash_source::has_prevout() const NOEXCEPT
{
    return !is_null((*input_)->prevout);
}

void transaction::sighash_source::write_prevout_script(
    writer& sink) const NOEXCEPT
{
    BC_ASSERT(has_prevout());
    (*input_)->prevout->script().to_data(sink, true);
}

bool transaction::sighash_source::has_annex() const NOEXCEPT
{
    return static_cast<bool>((*input_)->witness().annex());
}

hash_digest transaction::sighash_source::annex_hash() const NOEXCEPT
{
    return (*input_)->witness().annex().hash(true);
}

hash_digest transaction::sighash_source::double_hash_output(
    size_t output) const NOEXCEPT
{
    hash_digest digest{};
    stream::out::fast stream{ digest };
    hash::sha256x2::fast sink{ stream };
    write_output(sink, output);

    sink.flush();
    return digest;
}

} // namespace chain
} // namespace system
} // namespace libbitcoin
