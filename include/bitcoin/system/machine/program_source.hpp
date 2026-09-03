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
#ifndef LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_SOURCE_HPP
#define LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_SOURCE_HPP

#include <iterator>
#include <span>
#include <bitcoin/system/chain/chain.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/hash/hash.hpp>

namespace libbitcoin {
namespace system {
namespace machine {

/// Owning transaction/script projection used by machine::program.
/// The transaction and selected input must outlive this object. Script
/// and witness ownership is retained by shared immutable handles.
class program_source final
{
public:
    using transaction = chain::transaction;
    using input_iterator = chain::input_cptrs::const_iterator;
    using input_type = chain::input;
    using script = chain::script;
    using script_handle = script::cptr;
    using operation = chain::operation;
    using op_iterator = chain::operations::const_iterator;
    using witness = chunk_cptrs_ptr;

    static input_iterator to_input(const transaction& tx,
        size_t index) NOEXCEPT
    {
        return std::next(tx.inputs_ptr()->begin(), index);
    }

    program_source(const transaction& tx, const input_iterator& input)
        NOEXCEPT
      : tx_(tx), input_(input), script_((*input)->script_ptr()),
        value_(max_uint64), version_(chain::script_version::unversioned),
        spender_(true)
    {
        reset();
    }

    program_source(const program_source& other,
        const script_handle& script) NOEXCEPT
      : tx_(other.tx_), input_(other.input_), script_(script),
        value_(other.value_), version_(other.version_),
        witness_(other.witness_), tapleaf_(other.tapleaf_)
    {
        reset();
    }

    program_source(const transaction& tx, const input_iterator& input,
        const script_handle& script, chain::script_version version,
        const chunk_cptrs_ptr& witness, const hash_cptr& tapleaf={}) NOEXCEPT
      : tx_(tx), input_(input), script_(script),
        value_((*input)->prevout->value()), version_(version),
        witness_(witness), tapleaf_(tapleaf)
    {
        reset();
    }

    const transaction& tx() const NOEXCEPT
    {
        return tx_;
    }

    const input_type& input() const NOEXCEPT
    {
        return **input_;
    }

    const script& script_ref() const NOEXCEPT
    {
        return *script_;
    }

    bool has_prevout() const NOEXCEPT
    {
        return input().prevout != nullptr;
    }

    script_handle prevout_script() const NOEXCEPT
    {
        BC_ASSERT(has_prevout());
        return input().prevout->script_ptr();
    }

    bool script_empty() const NOEXCEPT
    {
        return script_->ops().empty();
    }

    bool witness_empty() const NOEXCEPT
    {
        return input().witness().stack().empty();
    }

    bool is_pay_to_script_hash(uint32_t active_flags) const NOEXCEPT
    {
        return script_->is_pay_to_script_hash(active_flags);
    }

    bool is_pay_to_witness(uint32_t active_flags) const NOEXCEPT
    {
        return script_->is_pay_to_witness(active_flags);
    }

    bool is_relaxed_push_pattern() const NOEXCEPT
    {
        return script::is_relaxed_push_pattern(script_->ops());
    }

    bool is_nominal_push_pattern() const NOEXCEPT
    {
        return script::is_nominal_push_pattern(script_->ops());
    }

    chain::script_version version(const script_handle& program) const NOEXCEPT
    {
        return program->version();
    }

    script_handle to_script(const data_slice& data) const NOEXCEPT
    {
        return to_shared<script>(data, false);
    }

    code extract_segwit(script_handle& out_script, witness& out_stack,
        const script_handle& program) const NOEXCEPT
    {
        return input().witness().extract_segwit(out_script, out_stack,
            *program);
    }

    code extract_taproot(hash_cptr& out_leaf, script_handle& out_script,
        witness& out_stack, const script_handle& program,
        const signatures& capture) const NOEXCEPT
    {
        return input().witness().extract_taproot(out_leaf, out_script,
            out_stack, *program, capture);
    }

    bool is_input_script() const NOEXCEPT
    {
        return spender_;
    }

    bool input_final() const NOEXCEPT
    {
        return input().is_final();
    }

    uint32_t input_sequence() const NOEXCEPT
    {
        return input().sequence();
    }

    uint32_t transaction_version() const NOEXCEPT
    {
        return tx_.version();
    }

    uint32_t transaction_locktime() const NOEXCEPT
    {
        return tx_.locktime();
    }

    size_t witness_size() const NOEXCEPT
    {
        return input().witness().serialized_size(true);
    }

    bool is_witness_push_size() const NOEXCEPT
    {
        BC_ASSERT(witness_);
        return chain::witness::is_push_size(*witness_);
    }

    template <typename Stack>
    Stack initial_stack() const NOEXCEPT
    {
        BC_ASSERT(witness_);
        return projection<Stack>(*witness_);
    }

    void set_subscript(size_t position) NOEXCEPT
    {
        const auto& ops = script_->ops();
        BC_ASSERT(position < ops.size());
        script_->offset = std::next(ops.begin(), add1(position));
    }

    template <typename Primary>
    void push_operation(Primary& primary, const operation& op) const NOEXCEPT
    {
        primary.emplace_chunk(op.data_ptr());
    }

    bool signature_hash(hash_digest& out, uint8_t sighash_flags,
        uint32_t active_flags) const NOEXCEPT
    {
        return generate(out, *script_, sighash_flags, active_flags);
    }

    bool signature_hash(hash_digest& out, const data_slice& endorsement,
        uint8_t sighash_flags, uint32_t active_flags) const NOEXCEPT
    {
        return generate(out, *subscript(endorsement, active_flags),
            sighash_flags, active_flags);
    }

    bool signature_hash(hash_digest& out,
        std::span<const data_slice> endorsements,
        uint8_t sighash_flags, uint32_t active_flags) const NOEXCEPT
    {
        return generate(out, *subscript(endorsements, active_flags),
            sighash_flags, active_flags);
    }

    bool is_pay_public_key_pattern() const NOEXCEPT
    {
        return script::is_pay_public_key_pattern(script_->ops());
    }

    bool is_pay_key_hash_pattern() const NOEXCEPT
    {
        return script::is_pay_key_hash_pattern(script_->ops());
    }

    bool is_pay_multisig_standard_pattern() const NOEXCEPT
    {
        return script::is_pay_multisig_standard_pattern(script_->ops());
    }

    bool is_pay_taproot_key_path_pattern() const NOEXCEPT
    {
        return script::is_pay_taproot_key_path_pattern(script_->ops());
    }

    bool is_pay_tapscript_single_pattern() const NOEXCEPT
    {
        return script::is_pay_tapscript_single_pattern(script_->ops());
    }

    bool is_pay_tapscript_timelock_pattern() const NOEXCEPT
    {
        return script::is_pay_tapscript_timelock_pattern(script_->ops());
    }

    bool is_pay_tapscript_inscription_pattern() const NOEXCEPT
    {
        return script::is_pay_tapscript_inscription_pattern(script_->ops());
    }

    chain::opcode extract_tapscript_threshold(size_t& min,
        size_t& max) const NOEXCEPT
    {
        return script_->extract_tapscript_threshold(min, max);
    }

    void log(const chain::signatures& capture) const NOEXCEPT
    {
        capture.log(*script_);
    }

private:
    void reset() NOEXCEPT
    {
        script_->clear_offset();
    }

    bool generate(hash_digest& out, const script& subscript,
        uint8_t sighash_flags, uint32_t active_flags) const NOEXCEPT
    {
        return tx_.signature_hash(out, input_, subscript, value_, tapleaf_,
            version_, sighash_flags, active_flags);
    }

    script_handle subscript(const data_slice& endorsement,
        uint32_t active_flags) const NOEXCEPT
    {
        using namespace chain;
        if (script::is_enabled(active_flags, flags::bip143_rule) &&
            version_ == script_version::segwit)
            return script_;

        return stripped({ stripper{ endorsement },
            stripper{ opcode::codeseparator } });
    }

    script_handle subscript(std::span<const data_slice> endorsements,
        uint32_t active_flags) const NOEXCEPT
    {
        using namespace chain;
        if (script::is_enabled(active_flags, flags::bip143_rule) &&
            version_ == script_version::segwit)
            return script_;

        strippers strip{};
        strip.reserve(add1(endorsements.size()));
        for (const auto& endorsement: endorsements)
            strip.emplace_back(endorsement);

        strip.emplace_back(opcode::codeseparator);
        return stripped(strip);
    }

    script_handle stripped(const chain::strippers& strip) const NOEXCEPT
    {
        using namespace chain;
        const auto stop = script_->ops().end();
        const op_iterator start{ script_->offset };
        if (!is_intersecting<operations>(start, stop, strip))
            return script_;

        return to_shared<script>(difference<operations>(start, stop, strip));
    }

    const transaction& tx_;
    const input_iterator input_;
    const script_handle script_;
    const uint64_t value_;
    const chain::script_version version_;
    const chunk_cptrs_ptr witness_{};
    const hash_cptr tapleaf_{};
    const bool spender_{};
};

} // namespace machine
} // namespace system
} // namespace libbitcoin

#endif
