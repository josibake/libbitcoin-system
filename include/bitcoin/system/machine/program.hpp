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
#ifndef LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_HPP
#define LIBBITCOIN_SYSTEM_MACHINE_PROGRAM_HPP

#include <atomic>
#include <unordered_map>
#include <bitcoin/system/chain/chain.hpp>
#include <bitcoin/system/crypto/crypto.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/hash/hash.hpp>
#include <bitcoin/system/machine/program_source.hpp>
#include <bitcoin/system/machine/stack.hpp>

namespace libbitcoin {
namespace system {
namespace machine {

/// A set of three stacks (primary, alternate, conditional) for script state.
/// Primary stack is optimized by peekable, swappable, and eraseable elements.
template <typename Stack, typename Source = program_source>
class program
{
public:
    DELETE_COPY_MOVE_DESTRUCT(program);

    using source = Source;
    using script = typename source::script;
    using script_handle = typename source::script_handle;
    using transaction = typename source::transaction;
    using script_version = chain::script_version;
    using input_iterator = typename source::input_iterator;

    /// Input script (default/empty stack).
    program(const transaction& transaction, const input_iterator& input,
        uint32_t active_flags, const chain::signatures& capture) NOEXCEPT;

    /// Legacy p2sh or prevout script (copied input stack).
    program(const program& other, const script_handle& script) NOEXCEPT;

    /// Legacy p2sh or prevout script (moved input stack).
    program(program&& other, const script_handle& script) NOEXCEPT;

    /// Witness v0 (segwit) script.
    program(const transaction& transaction, const input_iterator& input,
        const script_handle& script, uint32_t active_flags,
        script_version version, const chunk_cptrs_ptr& stack,
        const chain::signatures& capture) NOEXCEPT;

    /// Witness v1 (tapscript) script.
    program(const transaction& transaction, const input_iterator& input,
        const script_handle& script, uint32_t active_flags,
        script_version version, const chunk_cptrs_ptr& stack,
        const hash_cptr& tapleaf, const chain::signatures& capture) NOEXCEPT;

    /// Program result.
    virtual bool is_true(bool clean) const NOEXCEPT;

    /// Transaction must pop top input stack element [bip16].
    virtual const data_chunk& pop() NOEXCEPT;

protected:
    using stack_value = typename stack<Stack>::variant;
    using flags = chain::flags;
    using opcode = chain::opcode;
    using operation = typename source::operation;
    using script_error_t = error::script_error_t;
    using op_iterator = typename source::op_iterator;
    using hash_cache = std::unordered_map<uint8_t, hash_digest>;

    static INLINE bool equal_chunks(const stack_value& left,
        const stack_value& right) NOEXCEPT;

    /// Constants.
    /// -----------------------------------------------------------------------
    virtual INLINE script_error_t initialize() const NOEXCEPT;
    virtual INLINE op_iterator begin() const NOEXCEPT;
    virtual INLINE op_iterator end() const NOEXCEPT;
    virtual INLINE const transaction& tx() const NOEXCEPT;
    virtual INLINE const typename source::input_type& input() const NOEXCEPT;
    virtual INLINE bool input_final() const NOEXCEPT;
    virtual INLINE uint32_t input_sequence() const NOEXCEPT;
    virtual INLINE uint32_t transaction_version() const NOEXCEPT;
    virtual INLINE uint32_t transaction_locktime() const NOEXCEPT;
    virtual INLINE bool is_enabled(flags flag) const NOEXCEPT;

    /// Primary stack.
    /// -----------------------------------------------------------------------
    /// Underscored names reflect lack of guard against empty stack.

    /// Primary stack (push).
    virtual INLINE void push_operation(const operation& op) NOEXCEPT;
    virtual INLINE void push_chunk(data_chunk&& datum) NOEXCEPT;
    virtual INLINE void push_chunk(const chunk_cptr& datum) NOEXCEPT;
    virtual INLINE void push_bool(bool value) NOEXCEPT;
    virtual INLINE void push_signed64(int64_t value) NOEXCEPT;
    virtual INLINE void push_length(size_t value) NOEXCEPT;

    /// Primary stack (pop).
    virtual INLINE chunk_xptr pop_chunk_() NOEXCEPT;
    virtual INLINE data_slice pop_slice_() NOEXCEPT;
    virtual INLINE bool pop_strict_bool_() NOEXCEPT;
    virtual INLINE bool pop_bool_(bool& value, bool minimal) NOEXCEPT;
    virtual INLINE bool pop_chunks(chunk_xptrs& data, size_t count) NOEXCEPT;
    virtual INLINE bool pop_signed32(int32_t& value) NOEXCEPT;
    virtual INLINE bool pop_signed32_(int32_t& value) NOEXCEPT;
    virtual INLINE bool pop_binary32(int32_t& left, int32_t& right) NOEXCEPT;
    virtual INLINE bool pop_ternary32(int32_t& upper, int32_t& lower,
        int32_t& value) NOEXCEPT;
    virtual INLINE bool pop_index32(size_t& index) NOEXCEPT;

    /// Primary stack (peek).
    virtual INLINE bool peek_bool_() const NOEXCEPT;
    virtual INLINE bool peek_unsigned32(uint32_t& value) const NOEXCEPT;
    virtual INLINE bool peek_unsigned40(uint64_t& value) const NOEXCEPT;
    virtual INLINE size_t peek_size() const NOEXCEPT;

    /// Primary stack (variant - index).
    virtual INLINE void swap_(size_t left_index, size_t right_index) NOEXCEPT;
    virtual INLINE void erase_(size_t index) NOEXCEPT;
    virtual INLINE const stack_value& peek_() const NOEXCEPT;
    virtual INLINE const stack_value& peek_(size_t index) const NOEXCEPT;

    /// Primary stack (variant - top).
    virtual INLINE void drop_() NOEXCEPT;
    virtual INLINE void push_variant(const stack_value& vary) NOEXCEPT;
    virtual INLINE stack_value pop_() NOEXCEPT;

    /// Primary stack state (untyped).
    virtual INLINE size_t stack_size() const NOEXCEPT;
    virtual INLINE size_t stack_nonempty() const NOEXCEPT;
    virtual INLINE bool is_stack_empty() const NOEXCEPT;
    virtual INLINE bool is_stack_overflow() const NOEXCEPT;

    /// Alternate stack.
    /// -----------------------------------------------------------------------
    virtual INLINE bool is_alternate_empty() const NOEXCEPT;
    virtual INLINE void push_alternate(stack_value&& vary) NOEXCEPT;
    virtual INLINE stack_value pop_alternate_() NOEXCEPT;

    /// Conditional stack.
    /// -----------------------------------------------------------------------
    virtual INLINE void begin_if(bool value) NOEXCEPT;
    virtual INLINE void else_if_() NOEXCEPT;
    virtual INLINE void end_if_() NOEXCEPT;
    virtual INLINE bool is_balanced() const NOEXCEPT;
    virtual INLINE bool is_success() const NOEXCEPT;
    virtual INLINE bool if_(const operation& op) const NOEXCEPT;

    /// Accumulators.
    /// -----------------------------------------------------------------------
    virtual INLINE bool sigops_increment() NOEXCEPT;
    virtual INLINE bool ops_increment(const operation& op) NOEXCEPT;
    virtual INLINE bool ops_increment(size_t public_keys) NOEXCEPT;

    /// Endorsement parsing.
    /// -----------------------------------------------------------------------

    /// Parse schnorr endorsement into ec signature and signature hash flags.
    virtual INLINE const ec_signature& schnorr_split(uint8_t& sighash_flags,
        const data_slice& endorsement) const NOEXCEPT;

    /// Parse ecdsa endorsement into der signature and signature hash flags.
    virtual INLINE data_slice ecdsa_split(uint8_t& sighash_flags,
        const data_slice& endorsement) const NOEXCEPT;

    /// Parse der signature into ec signature and signature hash flags.
    virtual INLINE bool decode_signature(ec_signature& out,
        const data_slice& der_signature, bool strict) const NOEXCEPT;

    /// Signature subscripting.
    /// -----------------------------------------------------------------------

    /// Set subscript position to the op after the given position.
    virtual INLINE void set_subscript(size_t position) NOEXCEPT;

    /// Signature hashing.
    /// -----------------------------------------------------------------------
    virtual INLINE bool signature_hash(hash_digest& out,
        uint8_t sighash_flags) const NOEXCEPT;
    virtual INLINE bool signature_hash(hash_digest& out,
        const chunk_xptr& endorsement, uint8_t sighash_flags) const NOEXCEPT;
    virtual INLINE bool signature_hash(hash_digest& out,
        const chunk_xptrs& endorsements,
        uint8_t sighash_flags) const NOEXCEPT;

    /// Multisig signature hash caching.
    /// -----------------------------------------------------------------------
    virtual INLINE bool cached(uint8_t sighash_flags) const NOEXCEPT;
    virtual INLINE void uncache() const NOEXCEPT;
    virtual INLINE const hash_digest& cached_hash() const NOEXCEPT;
    virtual INLINE bool set_hash(uint8_t sighash_flags) const NOEXCEPT;
    virtual INLINE void set_hash(const chunk_xptrs& endorsements,
        uint8_t sighash_flags) const NOEXCEPT;

    /// Signature verify (with batching).
    /// -----------------------------------------------------------------------
    virtual inline bool verify_ecdsa_signature(const data_slice& point,
        const hash_digest& hash, const ec_signature& signature,
        bool capture=true) const NOEXCEPT;
    virtual inline bool try_batch_multisig_verification(const chunk_xptrs& points,
        const chunk_xptrs& endorsements) const NOEXCEPT;
    virtual inline bool verify_schnorr_signature(const data_slice& point,
        const hash_digest& hash, const ec_signature& signature) const NOEXCEPT;

private:
    static constexpr auto relaxed = std::memory_order_relaxed;
    static constexpr auto bip342_mask = bit_not<uint32_t>(flags::bip342_rule);
    using keys_array = std::array<ec_compressed, chain::multisig::maximum>;
    using sigs_array = std::array<ec_signature, chain::multisig::maximum>;
    using primary_stack = stack<Stack>;
    using secondary_stack = std::vector<stack_value>;
    struct multisig_cache
    {
        bool set{};
        uint8_t flags{};
        hash_digest hash{};
    };

    // Verify helpers.
    static inline bool is_schnorr_sighash(uint8_t sighash_flags) NOEXCEPT;

    // Batching helpers.
    inline bool parse_ecdsa_multisig(hash_digest& hash, keys_array& keys,
        sigs_array& sigs, const chunk_xptrs& points,
        const chunk_xptrs& endorsements) const NOEXCEPT;
    inline bool parse_ecdsa_signatures(uint8_t& sighash, sigs_array& out,
        const chunk_xptrs& endorsements, bool strict) const NOEXCEPT;
    inline bool compress_public_keys(keys_array& out,
        const chunk_xptrs& keys) const NOEXCEPT;
    inline bool to_compressed(ec_compressed& out,
        const data_slice& point) const NOEXCEPT;
    inline const ec_xonly& as_xonly(const data_slice& point) const NOEXCEPT;

    // Batching properties.
    inline bool is_threshold_batchable() const NOEXCEPT;
    inline bool is_multisig_batchable() const NOEXCEPT;
    inline bool is_schnorr_batchable() const NOEXCEPT;
    inline bool is_ecdsa_batchable() const NOEXCEPT;
    inline bool is_input_script() const NOEXCEPT;

    // Stack helpers.
    INLINE void push_chunk(const chunk_xptr& datum) NOEXCEPT;
    INLINE chunk_xptr peek_chunk_() const NOEXCEPT;
    INLINE bool peek_signed32_(int32_t& value) const NOEXCEPT;
    INLINE bool peek_signed40_(int64_t& value) const NOEXCEPT;
    INLINE bool is_stack_clean() const NOEXCEPT;

    // Constants.
    source source_;
    const uint32_t flags_;
    const bool witness_push_size_{ true };
    const chain::signatures& capture_;

    // Caches.
    mutable multisig_cache multisig_{};
    mutable chain::threshold threshold_{};

    // Stacks (primary_ is propagated).
    primary_stack primary_;
    secondary_stack alternate_{};
    condition_stack condition_{};

    // Accumulators.
    size_t budget_{};
    size_t operations_{};
    size_t negative_conditions_{};
};

} // namespace machine
} // namespace system
} // namespace libbitcoin

#define TEMPLATE template <typename Stack, typename Source>
#define CLASS program<Stack, Source>

#include <bitcoin/system/impl/machine/program.ipp>
#include <bitcoin/system/impl/machine/program_batch.ipp>
#include <bitcoin/system/impl/machine/program_construct.ipp>
#include <bitcoin/system/impl/machine/program_verify.ipp>

#undef CLASS
#undef TEMPLATE

#endif
