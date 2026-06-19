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
#include "../../test.hpp"
#include "silent_payment_vectors.hpp"

BOOST_AUTO_TEST_SUITE(silent_payment_tests)

namespace json = boost::json;
using namespace system::chain;
using silent_payment = system::wallet::silent_payment;

class silent_payment_accessor
  : public silent_payment
{
public:
    using silent_payment::copy_compressed;
    using silent_payment::copy_xonly;
    using silent_payment::to_even_compressed;
};

struct vector_input
{
    const char* txid;
    uint32_t vout;
    const char* input_script;
    const char* witness;
    const char* prevout;
};

static data_chunk chunk(const std::string_view& text)
{
    data_chunk out{};
    BOOST_REQUIRE(decode_base16(out, text));
    return out;
}

static hash_digest digest(const std::string_view& text)
{
    hash_digest out{};
    BOOST_REQUIRE(decode_hash(out, text));
    return out;
}

template <size_t Size>
static data_array<Size> bytes(const std::string_view& text)
{
    data_array<Size> out{};
    BOOST_REQUIRE(decode_base16(out, text));
    return out;
}

static script to_script(const char* text)
{
    return { chunk(text), false };
}

static witness to_witness(const char* text)
{
    return is_null(text) || text[0] == '\0' ?
        witness{} :
        witness{ chunk(text), true };
}

static input to_input(const vector_input& value)
{
    input in
    {
        { digest(value.txid), value.vout },
        to_script(value.input_script),
        to_witness(value.witness),
        max_uint32
    };

    in.prevout = to_shared<output>(0u, to_script(value.prevout));
    return in;
}

static output to_scan_output(const char* key)
{
    const auto text = std::string{ "5120" }.append(key);
    return { 0u, to_script(text.c_str()) };
}

static std::string text(const json::string& value)
{
    return { value.data(), value.size() };
}

static std::string text_at(const json::object& object, const char* key)
{
    return text(object.at(key).as_string());
}

static uint32_t uint32_at(const json::object& object, const char* key)
{
    const auto value = object.at(key).as_int64();
    BOOST_REQUIRE(value >= 0);
    BOOST_REQUIRE(value <= max_uint32);
    return static_cast<uint32_t>(value);
}

static bool value_is_null(const json::object& object, const char* key)
{
    const auto* value = object.if_contains(key);
    return value == nullptr || value->is_null();
}

static const json::array& bip352_vectors()
{
    static const auto vectors =
        json::parse(bip352::bip352_send_and_receive_vectors);
    return vectors.as_array();
}

static input to_input(const json::object& value)
{
    const auto input_script = text_at(value, "scriptSig");
    const auto witness_text = text_at(value, "txinwitness");
    const auto& prevout = value.at("prevout").as_object();
    const auto& script_pubkey = prevout.at("scriptPubKey").as_object();
    const auto prevout_script = text_at(script_pubkey, "hex");

    input in
    {
        { digest(text_at(value, "txid")), uint32_at(value, "vout") },
        to_script(input_script.c_str()),
        to_witness(witness_text.c_str()),
        max_uint32
    };

    in.prevout = to_shared<output>(0u, to_script(prevout_script.c_str()));
    return in;
}

static inputs to_inputs(const json::array& values)
{
    inputs out{};
    out.reserve(values.size());

    for (const auto& value: values)
        out.push_back(to_input(value.as_object()));

    return out;
}

static outputs to_outputs(const json::array& values)
{
    outputs out{};
    out.reserve(values.size());

    for (const auto& value: values)
        out.push_back(to_scan_output(
            text(value.as_string()).c_str()));

    return out;
}

static transaction to_transaction(const json::object& given)
{
    return
    {
        2u,
        to_inputs(given.at("vin").as_array()),
        to_outputs(given.at("outputs").as_array()),
        0u
    };
}

static std_vector<uint32_t> to_labels(const json::array& values)
{
    std_vector<uint32_t> out{};
    out.reserve(values.size());

    for (const auto& value: values)
    {
        const auto label = value.as_int64();
        BOOST_REQUIRE(label >= 0);
        BOOST_REQUIRE(label <= max_uint32);
        out.push_back(static_cast<uint32_t>(label));
    }

    return out;
}

static silent_payment::output_prefixes to_prefixes(const json::array& values)
{
    silent_payment::output_prefixes out{};
    out.reserve(values.size());

    for (const auto& value: values)
    {
        const auto key = bytes<ec_xonly_size>(text(value.as_string()));
        out.push_back(silent_payment::to_output_prefix(key));
    }

    return out;
}

static void require_prefixes_equal(
    const silent_payment::output_prefixes& left,
    const silent_payment::output_prefixes& right)
{
    BOOST_REQUIRE_EQUAL(left.size(), right.size());

    auto left_it = left.begin();
    auto right_it = right.begin();
    for (; left_it != left.end(); ++left_it, ++right_it)
        BOOST_REQUIRE_EQUAL(*left_it, *right_it);
}

static bool expected_candidate(const json::object& expected)
{
    if (!value_is_null(expected, "n_outputs"))
        return expected.at("n_outputs").as_int64() > 0;

    return !expected.at("outputs").as_array().empty();
}

static void require_bip352_receiving_vector(const json::object& given,
    const json::object& expected)
{
    const auto& material = given.at("key_material").as_object();
    const auto scan_secret = bytes<ec_secret_size>(
        text_at(material, "scan_priv_key"));
    const auto spend_secret = bytes<ec_secret_size>(
        text_at(material, "spend_priv_key"));

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend_secret));

    silent_payment::scan_record record{};
    const auto tx = to_transaction(given);
    const auto has_record = silent_payment::compute_scan_record(record, tx);

    if (value_is_null(expected, "tweak"))
    {
        BOOST_REQUIRE(!has_record);
        return;
    }

    BOOST_REQUIRE(has_record);
    const auto prevouts_summary = bytes<ec_compressed_size>(
        text_at(expected, "tweak"));
    BOOST_REQUIRE_EQUAL(record.prevouts_summary, prevouts_summary);
    require_prefixes_equal(record.prefixes,
        to_prefixes(given.at("outputs").as_array()));

    ec_compressed shared_secret{ record.prevouts_summary };
    BOOST_REQUIRE(ec_multiply(shared_secret, scan_secret));
    const auto expected_shared = bytes<ec_compressed_size>(
        text_at(expected, "shared_secret"));
    BOOST_REQUIRE_EQUAL(shared_secret, expected_shared);

    const auto labels = to_labels(given.at("labels").as_array());
    silent_payment receiver{ scan_secret, spend_public, labels };
    BOOST_REQUIRE(receiver);

    bool matched{};
    BOOST_REQUIRE(receiver.match_prefixes(matched, record.prevouts_summary,
        record.prefixes));
    BOOST_REQUIRE_EQUAL(matched, expected_candidate(expected));
}

static void require_record(std::initializer_list<vector_input> inputs,
    std::initializer_list<const char*> outputs, const char* summary)
{
    chain::inputs tx_inputs{};
    tx_inputs.reserve(inputs.size());
    for (const auto& in: inputs)
        tx_inputs.push_back(to_input(in));

    chain::outputs tx_outputs{};
    tx_outputs.reserve(outputs.size());
    for (const auto& key: outputs)
        tx_outputs.push_back(to_scan_output(key));

    silent_payment::scan_record record{};
    const transaction tx{ 2u, std::move(tx_inputs), std::move(tx_outputs), 0u };
    BOOST_REQUIRE(!tx.is_coinbase());
    BOOST_REQUIRE(tx.outputs_ptr()->front()->script().output_pattern() ==
        script_pattern::pay_witness_v1_taproot);
    BOOST_REQUIRE(silent_payment::has_scan_outputs(tx));
    BOOST_REQUIRE(silent_payment::compute_scan_record(record, tx));
    BOOST_REQUIRE_EQUAL(record.prevouts_summary,
        bytes<ec_compressed_size>(summary));
    BOOST_REQUIRE_EQUAL(record.prefixes.size(), outputs.size());

    size_t index{};
    for (const auto& key: outputs)
    {
        BOOST_REQUIRE_EQUAL(record.prefixes[index],
            silent_payment::to_output_prefix(bytes<ec_xonly_size>(key)));
        ++index;
    }
}

static void require_no_record(std::initializer_list<vector_input> inputs)
{
    chain::inputs tx_inputs{};
    tx_inputs.reserve(inputs.size());
    for (const auto& in: inputs)
        tx_inputs.push_back(to_input(in));

    chain::outputs tx_outputs
    {
        to_scan_output(
            "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1")
    };

    silent_payment::scan_record record{};
    const transaction tx{ 2u, std::move(tx_inputs), std::move(tx_outputs), 0u };
    BOOST_REQUIRE(!silent_payment::compute_scan_record(record, tx));
}

static transaction transaction_with_inputs(chain::inputs&& tx_inputs,
    const char* output_script)
{
    return
    {
        2u,
        std::move(tx_inputs),
        { { 0u, to_script(output_script) } },
        0u
    };
}

BOOST_AUTO_TEST_CASE(silent_payment__copy_xonly__valid__expected)
{
    const auto expected = bytes<ec_xonly_size>(
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
    ec_xonly out{};

    BOOST_REQUIRE(silent_payment_accessor::copy_xonly(out, to_chunk(expected)));
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE(silent_payment__copy_xonly__short__false)
{
    ec_xonly out{};

    BOOST_REQUIRE(!silent_payment_accessor::copy_xonly(out, data_chunk{ 0x01 }));
}

BOOST_AUTO_TEST_CASE(silent_payment__copy_compressed__valid__expected)
{
    ec_compressed out{};

    BOOST_REQUIRE(silent_payment_accessor::copy_compressed(out,
        to_chunk(ec_compressed_generator)));
    BOOST_REQUIRE_EQUAL(out, ec_compressed_generator);
}

BOOST_AUTO_TEST_CASE(silent_payment__copy_compressed__uncompressed__false)
{
    ec_uncompressed uncompressed{};
    ec_compressed out{};

    BOOST_REQUIRE(decompress(uncompressed, ec_compressed_generator));
    BOOST_REQUIRE(!silent_payment_accessor::copy_compressed(out,
        to_chunk(uncompressed)));
}

BOOST_AUTO_TEST_CASE(silent_payment__to_even_compressed__generator_xonly__expected)
{
    const auto xonly = bytes<ec_xonly_size>(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    ec_compressed out{};

    BOOST_REQUIRE(silent_payment_accessor::to_even_compressed(out, xonly));
    BOOST_REQUIRE_EQUAL(out, ec_compressed_generator);
}

BOOST_AUTO_TEST_CASE(silent_payment__to_output_prefix__xonly__first_eight_big_endian)
{
    const auto key = bytes<ec_xonly_size>(
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");

    BOOST_REQUIRE_EQUAL(silent_payment::output_prefix_size, sizeof(uint64_t));
    BOOST_REQUIRE_EQUAL(silent_payment::to_output_prefix(key),
        0x0123456789abcdef_u64);
}

// BIP352 send_and_receive_test_vectors.json:
// "Simple send: two inputs"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__p2pkh_inputs__expected)
{
    require_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
            "",
            "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            0u,
            "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
            "",
            "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac"
        }
    },
    {
        "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"
    },
    "024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");
}

// "Outpoint ordering byte-lexicographically vs. vout-integer"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__lexicographic_outpoint__expected)
{
    require_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            1u,
            "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
            "",
            "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"
        },
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            256u,
            "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
            "",
            "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac"
        }
    },
    {
        "a85ef8701394b517a4b35217c4bd37ac01ebeed4b008f8d0879f9e09ba95319c"
    },
    "031f9a80d0938cf980b51f7cc4fad713d49037f430646dff129c0570d75a40d8f0");
}

// "Single recipient: taproot only inputs with even y-values"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__taproot_inputs__expected)
{
    require_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "",
            "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
            "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            0u,
            "",
            "0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1",
            "5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338"
        }
    },
    {
        "de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb"
    },
    "02dc59cc8e8873b65c1dd5c416d4fbeb647372c329bd84a70c05b310e222e2c183");
}

// "Single recipient: taproot only with mixed even/odd y-values"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__taproot_odd_key__expected)
{
    require_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "",
            "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
            "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            0u,
            "",
            "01400a4d0dca6293f40499394d7eefe14a1de11e0e3454f51de2e802592abf5ee549042a1b1a8fb2e149ee9dd3f086c1b69b2f182565ab6ecf599b1ec9ebadfda6c5",
            "51208c8d23d4764feffcd5e72e380802540fa0f88e3d62ad5e0b47955f74d7b283c4"
        }
    },
    {
        "77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1"
    },
    "03b990f5b1d90ea8fd4bdd5c856a9dfe17035d196958062e2c6cb4c99e413f3548");
}

// "Single recipient: taproot input with NUMS point"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__taproot_nums_input__skipped)
{
    require_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "",
            "0440c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00150",
            "5120da6f0595ecb302bbe73e2f221f05ab10f336b06817d36fd28fc6691725ddaa85"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            0u,
            "",
            "0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1",
            "5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            1u,
            "",
            "0340268d31a9276f6380107d5321cafa6d9e8e5ea39204318fdc8206b31507c891c3bbcea3c99e2208d73bd127a8e8c5f1e45a54f1bd217205414ddb566ab7eda0092220e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85dac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            "51200a3c9365ceb131f89b0a4feb6896ebd67bb15a98c31eaa3da143bb955a0f3fcb"
        }
    },
    {
        "79e79897c52935bfd97fc6e076a6431a0c7543ca8c31e0fc3cf719bb572c842d"
    },
    "02213b872c9a6ee28a0d861384a1b3e3ec7257f4855ed09b4323e3899f3b028989");
}

BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__taproot_nums_future_leaf__skipped)
{
    require_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "",
            "0440c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac21c350929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00150",
            "5120da6f0595ecb302bbe73e2f221f05ab10f336b06817d36fd28fc6691725ddaa85"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            0u,
            "",
            "0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1",
            "5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            1u,
            "",
            "0340268d31a9276f6380107d5321cafa6d9e8e5ea39204318fdc8206b31507c891c3bbcea3c99e2208d73bd127a8e8c5f1e45a54f1bd217205414ddb566ab7eda0092220e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85dac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            "51200a3c9365ceb131f89b0a4feb6896ebd67bb15a98c31eaa3da143bb955a0f3fcb"
        }
    },
    {
        "79e79897c52935bfd97fc6e076a6431a0c7543ca8c31e0fc3cf719bb572c842d"
    },
    "02213b872c9a6ee28a0d861384a1b3e3ec7257f4855ed09b4323e3899f3b028989");
}

// "Public key extraction from malleated p2pkh"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__malleated_p2pkh__expected)
{
    require_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
            "",
            "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"
        },
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            1u,
            "0075473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
            "",
            "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac"
        },
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            2u,
            "5163473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187372102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d67483046022100c0d3c851d3bd562ae93d56bcefd735ea57c027af46145a4d5e9cac113bfeb0c2022100ee5b2239af199fa9b7aa1d98da83a29d0a2cf1e4f29e2f37134ce386d51c544c2102ad0f26ddc7b3fcc340155963b3051b85289c1869612ecb290184ac952e2864ec68",
            "",
            "76a914c82c5ec473cbc6c86e5ef410e36f9495adcf979988ac"
        }
    },
    {
        "4612cdbf845c66c7511d70aab4d9aed11e49e48cdb8d799d787101cdd0d53e4f"
    },
    "028d6617f9bfe08604beb2188f4eebec923f5f8cc436fa6d14e4256e49bc32e7c8");
}

// "P2PKH and P2WPKH Uncompressed Keys are skipped"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__uncompressed_keys__skipped)
{
    require_record(
    {
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            0u,
            "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
            "",
            "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"
        },
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
            "",
            "76a9144b92ac4ac6fe6212393894addda332f2e47a315688ac"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            1u,
            "",
            "02473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187374104e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d6fe8190e189be57d0d5bcd17dbcbcd04c9b4a1c5f605b10d5c90abfcc0d12884",
            "00140423f731a07491364e8dce98b7c00bda63336950"
        }
    },
    {
        "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6"
    },
    "02b04034f00da0678507d1345b7d56fecef825a1151f9dc7d8ca6946452a9e1f43");
}

BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__noncontiguous_taproot_outputs__expected)
{
    chain::inputs tx_inputs
    {
        to_input(
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
            "",
            "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"
        })
    };
    const auto first = bytes<ec_xonly_size>(
        "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1");
    const auto second = bytes<ec_xonly_size>(
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
    const transaction tx
    {
        2u,
        std::move(tx_inputs),
        {
            to_scan_output(
                "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"),
            output{ 0u, to_script("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac") },
            to_scan_output(
                "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
        },
        0u
    };

    silent_payment::scan_record record{};
    BOOST_REQUIRE(silent_payment::compute_scan_record(record, tx));
    BOOST_REQUIRE_EQUAL(record.prefixes.size(), 2u);
    BOOST_REQUIRE_EQUAL(record.prefixes[0],
        silent_payment::to_output_prefix(first));
    BOOST_REQUIRE_EQUAL(record.prefixes[1],
        silent_payment::to_output_prefix(second));
}

// "No valid inputs, sender generates no outputs"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__no_valid_inputs__false)
{
    require_no_record(
    {
        {
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            0u,
            "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d641045a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5c61836c9b1688ba431f7ea3039742251f62f0dca3da1bee58a47fa9b456c2d52",
            "",
            "76a914460e8b41545d2dbe7e0671f0f573e2232814260a88ac"
        },
        {
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            0u,
            "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
            "",
            "76a9144b92ac4ac6fe6212393894addda332f2e47a315688ac"
        }
    });
}

// "Input keys sum up to zero / point at infinity: sending fails, receiver skips tx"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__input_sum_zero__false)
{
    require_no_record(
    {
        {
            "3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e",
            0u,
            "",
            "024730440220085003179ce1a3a88ce0069aa6ea045e140761ab88c22a26ae2a8cfe983a6e4602204a8a39940f0735c8a4424270ac8da65240c261ab3fda9272f6d6efbf9cfea366012102557ef3e55b0a52489b4454c1169e06bdea43687a69c1f190eb50781644ab6975",
            "00149d9e24f9fab4e35bf1a6df4b46cb533296ac0792"
        },
        {
            "3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e",
            1u,
            "",
            "0247304402204586a68e1d97dd3c6928e3622799859f8c3b20c3c670cf654cc905c9be29fdb7022043fbcde1689f3f4045e8816caf6163624bd19e62e4565bc99f95c533e599782c012103557ef3e55b0a52489b4454c1169e06bdea43687a69c1f190eb50781644ab6975",
            "00149860538b5575962776ed0814ae222c7d60c72d7b"
        }
    });
}

// "Input keys intermediate sum is zero but final sum is non-zero"
BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__intermediate_sum_zero__expected)
{
    require_record(
    {
        {
            "3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e",
            0u,
            "",
            "0247304402203e5537fa8c876b3475e7efe4f1474b0f48b7a6e4169179db5de9bb5b55ad1bd10220200e06f8f4d29dbc48bbcdf90df3278e798ce6cbf3c9fbf90427599fde147867012102557ef3e55b0a52489b4454c1169e06bdea43687a69c1f190eb50781644ab6975",
            "00149d9e24f9fab4e35bf1a6df4b46cb533296ac0792"
        },
        {
            "3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e",
            1u,
            "",
            "0247304402207fdad0faf46edc54f5a5c67d33b2fa8d3f1fdc869381fd96e659f9e0c470ab1e022044f0d973339618b18667cef9a6251817f7f431f7f2b252a8cb760ccb40e7d823012103557ef3e55b0a52489b4454c1169e06bdea43687a69c1f190eb50781644ab6975",
            "00149860538b5575962776ed0814ae222c7d60c72d7b"
        },
        {
            "3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e",
            2u,
            "",
            "0247304402203e5537fa8c876b3475e7efe4f1474b0f48b7a6e4169179db5de9bb5b55ad1bd10220200e06f8f4d29dbc48bbcdf90df3278e798ce6cbf3c9fbf90427599fde147867012102557ef3e55b0a52489b4454c1169e06bdea43687a69c1f190eb50781644ab6975",
            "00149d9e24f9fab4e35bf1a6df4b46cb533296ac0792"
        }
    },
    {
        "7e88a7536c90770be4d2693a84ed03abe3fdcc5a29f96ec3433effec3b0c2194"
    },
    "039c68bacb7efbf2175d781822f460afc4839a5798fabb055b50d939231bf57bb6");
}

BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__coinbase__false)
{
    silent_payment::scan_record record{};
    const transaction tx
    {
        2u,
        { input{} },
        {
            to_scan_output(
                "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1")
        },
        0u
    };

    BOOST_REQUIRE(tx.is_coinbase());
    BOOST_REQUIRE(!silent_payment::compute_scan_record(record, tx));
}

BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__no_scan_outputs__false)
{
    silent_payment::scan_record record{};
    const auto tx = transaction_with_inputs(
        {
            to_input(
            {
                "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                0u,
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                "",
                "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"
            })
        },
        "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac");

    BOOST_REQUIRE(!silent_payment::has_scan_outputs(tx));
    BOOST_REQUIRE(!silent_payment::compute_scan_record(record, tx));
}

BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__missing_prevout__false)
{
    silent_payment::scan_record record{};
    input in
    {
        { digest("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0u },
        script{},
        witness{},
        max_uint32
    };
    const transaction tx
    {
        2u,
        { in },
        {
            to_scan_output(
                "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1")
        },
        0u
    };

    BOOST_REQUIRE(!tx.inputs_ptr()->front()->prevout);
    BOOST_REQUIRE(!silent_payment::compute_scan_record(record, tx));
}

BOOST_AUTO_TEST_CASE(silent_payment__compute_scan_record__future_segwit_prevout__false)
{
    silent_payment::scan_record record{};
    const auto tx = transaction_with_inputs(
        {
            to_input(
            {
                "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                0u,
                "",
                "",
                "52203e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"
            })
        },
        "51203e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1");

    BOOST_REQUIRE(tx.inputs_ptr()->front()->prevout->script().version() ==
        script_version::reserved);
    BOOST_REQUIRE(!silent_payment::compute_scan_record(record, tx));
}

BOOST_AUTO_TEST_CASE(silent_payment__match_prefixes__unlabeled_candidate__true)
{
    const auto scan = base16_array(
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const auto spend = base16_array(
        "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    const auto prevouts_summary = base16_array(
        "024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend));

    silent_payment::output_prefixes prefixes
    {
        silent_payment::to_output_prefix(base16_array(
            "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))
    };

    silent_payment receiver{ scan, spend_public, { 0 } };
    BOOST_REQUIRE(receiver);
    bool prefix_matched{};
    BOOST_REQUIRE(receiver.match_prefixes(prefix_matched, prevouts_summary,
        prefixes));
    BOOST_REQUIRE(prefix_matched);
}

BOOST_AUTO_TEST_CASE(silent_payment__match_prefixes__labeled_candidate__true)
{
    const auto scan = base16_array(
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const auto spend = base16_array(
        "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    const auto prevouts_summary = base16_array(
        "0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend));

    silent_payment::output_prefixes prefixes
    {
        silent_payment::to_output_prefix(base16_array(
            "67626aebb3c4307cf0f6c39ca23247598fabf675ab783292eb2f81ae75ad1f8c"))
    };

    silent_payment receiver{ scan, spend_public, { 2, 3, 1001337 } };
    BOOST_REQUIRE(receiver);
    bool prefix_matched{};
    BOOST_REQUIRE(receiver.match_prefixes(prefix_matched, prevouts_summary,
        prefixes));
    BOOST_REQUIRE(prefix_matched);
}

BOOST_AUTO_TEST_CASE(
    silent_payment__match_prefixes__empty_labels_checks_change_label__true)
{
    const auto scan = base16_array(
        "11b7a82e06ca2648d5fded2366478078ec4fc9dc1d8ff487518226f229d768fd");
    const auto spend = base16_array(
        "b8f87388cbb41934c50daca018901b00070a5ff6cc25a7e9e716a9d5b9e4d664");
    const auto prevouts_summary = base16_array(
        "0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend));

    silent_payment::output_prefixes prefixes
    {
        silent_payment::to_output_prefix(base16_array(
            "be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff"))
    };

    silent_payment receiver{ scan, spend_public, {} };
    BOOST_REQUIRE(receiver);
    bool prefix_matched{};
    BOOST_REQUIRE(receiver.match_prefixes(prefix_matched, prevouts_summary,
        prefixes));
    BOOST_REQUIRE(prefix_matched);
}

BOOST_AUTO_TEST_CASE(silent_payment__construct__invalid_scan_secret__false)
{
    const auto spend = base16_array(
        "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend));

    const silent_payment receiver{ ec_secret{}, spend_public, { 0 } };
    BOOST_REQUIRE(!receiver);
}

BOOST_AUTO_TEST_CASE(silent_payment__construct__invalid_spend_key__false)
{
    const auto scan = base16_array(
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");

    const silent_payment receiver{ scan, null_ec_compressed, { 0 } };
    BOOST_REQUIRE(!receiver);
}

BOOST_AUTO_TEST_CASE(silent_payment__match_prefixes__empty_prefixes__false)
{
    const auto scan = base16_array(
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const auto spend = base16_array(
        "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    const auto prevouts_summary = base16_array(
        "024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend));

    silent_payment receiver{ scan, spend_public, { 0 } };
    BOOST_REQUIRE(receiver);

    bool prefix_matched{};
    BOOST_REQUIRE(receiver.match_prefixes(prefix_matched, prevouts_summary, {}));
    BOOST_REQUIRE(!prefix_matched);
}

BOOST_AUTO_TEST_CASE(silent_payment__match_prefixes__no_matching_prefix__false)
{
    const auto scan = base16_array(
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const auto spend = base16_array(
        "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    const auto prevouts_summary = base16_array(
        "024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend));

    silent_payment receiver{ scan, spend_public, { 0 } };
    BOOST_REQUIRE(receiver);

    silent_payment::output_prefixes prefixes
    {
        silent_payment::to_output_prefix(base16_array(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
    };
    bool prefix_matched{};
    BOOST_REQUIRE(receiver.match_prefixes(prefix_matched, prevouts_summary,
        prefixes));
    BOOST_REQUIRE(!prefix_matched);
}

BOOST_AUTO_TEST_CASE(silent_payment__match_prefixes__invalid_prevouts_summary__false)
{
    const auto scan = base16_array(
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const auto spend = base16_array(
        "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");

    ec_compressed spend_public{};
    BOOST_REQUIRE(secret_to_public(spend_public, spend));

    silent_payment receiver{ scan, spend_public, { 0 } };
    BOOST_REQUIRE(receiver);

    bool prefix_matched{ true };
    BOOST_REQUIRE(!receiver.match_prefixes(prefix_matched, null_ec_compressed,
        {}));
    BOOST_REQUIRE(!prefix_matched);
}

BOOST_AUTO_TEST_CASE(silent_payment__bip352_receiving_vectors__all__expected)
{
    for (const auto& value: bip352_vectors())
    {
        const auto& suite = value.as_object();
        const auto comment = text_at(suite, "comment");
        const auto& vectors = suite.at("receiving").as_array();

        size_t index{};
        for (const auto& receiving: vectors)
        {
            BOOST_TEST_CONTEXT("case: " << comment << ", receiving: " << index)
            {
                const auto& vector = receiving.as_object();
                require_bip352_receiving_vector(
                    vector.at("given").as_object(),
                    vector.at("expected").as_object());
            }

            ++index;
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
