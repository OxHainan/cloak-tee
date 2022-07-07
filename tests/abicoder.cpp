// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "abi/abicoder.h"

#include "abi/types/array.h"
#include "abi/types/type.h"
#include "eEVM/rlp.h"
#include "fmt/core.h"
#include "jsonrpc.h"
#include "string"

#include <doctest/doctest.h>
#include <eEVM/util.h>
#include <vector>

using namespace std;
using namespace eevm;

namespace abicoder
{
eevm::Address to_address(const vector<uint8_t>& inputs)
{
    return eevm::from_big_endian(inputs.data());
}

template <typename T>
void test_basic(Type* pd, const T&& correct)
{
    CHECK(pd->encode() == correct);
}

TEST_CASE("Test Address")
{
    string src = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
    auto correct = to_bytes(src, 12u);
    auto addr = Address(src);
    test_basic(&addr, move(correct));

    auto de_addr = Address();
    de_addr.decode(correct);
    CHECK(eevm::to_checksum_address(to_address(de_addr.encode())) == src);
}

TEST_CASE("Test Bool")
{
    SUBCASE("when paramters value is true")
    {
        string src = "0x1";
        auto correct = to_bytes(src, 31u);
        auto boolean = Boolean(true);
        test_basic(&boolean, move(correct));

        auto boolean1 = Boolean(src);
        test_basic(&boolean1, move(correct));

        auto de_boolean = Boolean();
        de_boolean.decode(correct);
        // CHECK(de_boolean.get_value());
    }

    SUBCASE("When paramters value is false")
    {
        string src = "0x0";
        auto correct = to_bytes(src, 31u);
        auto boolean = Boolean(false);
        test_basic(&boolean, move(correct));

        auto boolean1 = Boolean(src);
        test_basic(&boolean1, move(correct));

        auto de_boolean = Boolean();
        de_boolean.decode(correct);
        // CHECK(de_boolean.get_value() == false);
    }

    SUBCASE("When paramters value is 0x10")
    {
        string src = "0x10";
        CHECK_THROWS(Boolean(src));
    }
}

TEST_CASE("Test String")
{
    string src = "hello, world!";
    auto correct = eevm::to_bytes(
        "0x000000000000000000000000000000000000000000000000000000000000000d"
        "68656c6c6f2c20776f726c642100000000000000000000000000000000000000");
    auto utf8 = Utf8String(src);
    test_basic(&utf8, move(correct));

    auto de_utf8 = Utf8String();
    de_utf8.decode(correct);
    CHECK(de_utf8.get_value() == std::vector<uint8_t>(src.begin(), src.end()));
}

TEST_CASE("Test dynamic bytes")
{
    string src = "hello, world!";
    auto correct = eevm::to_bytes(
        "0x000000000000000000000000000000000000000000000000000000000000000d"
        "68656c6c6f2c20776f726c642100000000000000000000000000000000000000");

    auto bytes = DynamicBytes(src);
    test_basic(&bytes, move(correct));

    auto de_bytes = DynamicBytes();
    de_bytes.decode(correct);
    CHECK(de_bytes.get_value() == std::vector<uint8_t>(src.begin(), src.end()));
}

TEST_CASE("Test static bytes")
{
    string src = "1234567890";
    auto correct = eevm::to_bytes(
        "0x3132333435363738393000000000000000000000000000000000000000000000");

    auto bytes = Bytes(10, src);
    test_basic(&bytes, move(correct));

    auto de_bytes = Bytes(10);
    de_bytes.decode(correct);
    CHECK(de_bytes.get_value() == std::vector<uint8_t>(src.begin(), src.end()));
}

TEST_CASE("Test uint")
{
    auto src = eevm::to_uint256("69");
    auto correct = eevm::to_bytes(
        "0x0000000000000000000000000000000000000000000000000000000000000045");
    // uint256
    auto uint_ = Uint(src);
    test_basic(&uint_, move(correct));

    // string
    auto uint_1 = Uint("0x45");
    test_basic(&uint_1, move(correct));

    // vector<uint8_t>
    std::vector<uint8_t> src1({0x45});
    auto uint_2 = Uint(src1);
    test_basic(&uint_2, move(correct));

    // to_uint64
    CHECK(NumericType(correct).to_uint64() == 69); // NOLINT
}

TEST_CASE("Test dynamic array")
{
    auto one =
        {"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
         "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"};

    SUBCASE("One-dimensional")
    {
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "02"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");

        auto array = DynamicArray(common_type("address"), one);
        test_basic(&array, move(correct));
    }

    SUBCASE("Two-dimensional")
    {
        auto src = {one, one};
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "02"
            "0000000000000000000000000000000000000000000000000000000000000040"
            "00000000000000000000000000000000000000000000000000000000000000a0"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");

        auto array = DynamicArray(make_common_array("address"), src);
        test_basic(&array, move(correct));
    }

    SUBCASE("Three-dimensional")
    {
        vector<vector<string>> src = {
            {"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"}};

        vector<vector<vector<string>>> vec = {src, src};
        auto correct = eevm::to_bytes(
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000000000000000040"
            "00000000000000000000000000000000000000000000000000000000000000c0"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");

        auto array = DynamicArray(make_common_array("address", {0, 0}), vec);
        test_basic(&array, move(correct));
    }
}

TEST_CASE("Test static array")
{
    auto one = {"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"};
    SUBCASE("One-dimensional")
    {
        auto correct = eevm::to_bytes(
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");

        auto array = StaticArray(common_type("address"), one);
        CHECK_FALSE(array.dynamicType()); // address[1] false
        test_basic(&array, move(correct));

        auto correct1 = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "20"
            "0000000000000000000000000000000000000000000000000000000000000014"
            "de0b295669a9fd93d5f28d9ec85e40f4cb697bae00000000000000000000000"
            "0");

        auto array1 = StaticArray(common_type("bytes"), one); // bytes[1] true
        CHECK(array1.dynamicType());
        CHECK(array1.encode() == correct1);
    }

    auto two = {one, one};
    SUBCASE("Two-dimensional")
    {
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "40"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");

        auto array =
            StaticArray(make_common_array("address"), two); // address[][2] true
        CHECK(array.dynamicType());
        test_basic(&array, move(correct));

        auto array1 = StaticArray(make_common_array("address", {1}), two);
        auto correct1 = eevm::to_bytes(
            "0x000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697b"
            "ae"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");
        CHECK_FALSE(array1.dynamicType());
        test_basic(&array1, move(correct1));
    }

    SUBCASE("Three-dimensional")
    {
        auto src = {two, two};
        auto correct = eevm::to_bytes(
            "0000000000000000000000000000000000000000000000000000000000000040"
            "0000000000000000000000000000000000000000000000000000000000000120"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000000000000000040"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000000000000000040"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");

        auto array =
            StaticArray(make_common_array("address", {0, 0}), src); // address[][][2]
                                                                    // true
        CHECK(array.dynamicType());
        test_basic(&array, move(correct));
    }
}

TEST_CASE("Test encode")
{
    auto encoder = Encoder("test");
    SUBCASE("encoder one")
    {
        std::vector<std::string> arrs =
            {"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
             "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"};

        encoder.add_inputs("a", "uint", "0x123", number_type());
        encoder.add_inputs(
            "b", "address[2]", arrs, make_common_array("address", {2}));
        encoder
            .add_inputs("c", "bytes10", "1234567890", common_type("bytes", 10));
        encoder
            .add_inputs("d", "string", "Hello, world!", common_type("string"));

        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000001"
            "23"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "3132333435363738393000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000a0"
            "000000000000000000000000000000000000000000000000000000000000000d"
            "48656c6c6f2c20776f726c64210000000000000000000000000000000000000"
            "0");

        CHECK(encoder.encode() == correct);
    }

    SUBCASE("encoder two")
    {
        vector<vector<std::string>> arrs =
            {{"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"},
             {"0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"}};
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "20"
            "0000000000000000000000000000000000000000000000000000000000000040"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697ba"
            "e");

        encoder.add_inputs(
            "b", "address[][2]", arrs, make_common_array("address", {0, 2}));
        CHECK(encoder.encode() == correct);
    }

    SUBCASE("test string nil")
    {
        string src = "";
        encoder.add_inputs("a", "string", src, common_type("string"));
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "20"
            "000000000000000000000000000000000000000000000000000000000000000"
            "0");

        CHECK(encoder.encode() == correct);
    }

    SUBCASE("test string value is 0x")
    {
        string src = "0x";
        encoder.add_inputs("a", "string", src, common_type("string"));
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "20"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "307800000000000000000000000000000000000000000000000000000000000"
            "0");

        CHECK(encoder.encode() == correct);
    }

    SUBCASE("test bytes nil")
    {
        string src = "0x";
        encoder.add_inputs("a", "bytes", src, common_type("bytes"));
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "20"
            "000000000000000000000000000000000000000000000000000000000000000"
            "0"); // 0x

        CHECK(encoder.encode() == correct);
    }

    SUBCASE("test dynamic array when bytes type value is nil")
    {
        vector<string> src = {};

        encoder.add_inputs("a", "bytes[]", src, make_bytes_array());
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "20"
            "000000000000000000000000000000000000000000000000000000000000000"
            "0");
        CHECK(encoder.encode() == correct);
    }

    SUBCASE("test dynamic array when string type value is nil")
    {
        vector<string> src = {};

        encoder.add_inputs("a", "string[]", src, make_common_array("string"));
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "20"
            "000000000000000000000000000000000000000000000000000000000000000"
            "0");
        CHECK(encoder.encode() == correct);
    }

    SUBCASE("test static array when string type value is nil")
    {
        vector<string> src = {};
        CHECK_THROWS(encoder.add_inputs(
            "a",
            "string[2]",
            src,
            make_common_array("string", {2}))); // static array
    }
}

TEST_CASE("Test function")
{
    auto func = Decoder();
    SUBCASE("Include static array")
    {
        func.add_params("a", "uint256", number_type());
        func.add_params(
            "address", "address[2]", make_common_array("address", {2}));
        func.add_params("c", "bytes", common_type("bytes"));
        func.add_params("d", "uint", number_type());
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "02"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "00000000000000000000000000000000000000000000000000000000000000a0"
            "0000000000000000000000000000000000000000000000000000000000006981"
            "000000000000000000000000000000000000000000000000000000000000000d"
            "68656c6c6f2c20776f726c64210000000000000000000000000000000000000"
            "0");
        func.decode(correct);
    }

    SUBCASE("Include dynamic array")
    {
        func.add_params("a", "uint256", number_type());
        func.add_params("address", "address[]", make_common_array("address"));
        func.add_params("c", "bytes", common_type("bytes"));
        func.add_params("d", "uint", number_type());
        auto correct = eevm::to_bytes(
            "0x00000000000000000000000000000000000000000000000000000000000000"
            "02"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "00000000000000000000000000000000000000000000000000000000000000e0"
            "0000000000000000000000000000000000000000000000000000000000006981"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "000000000000000000000000de0b295669a9fd93d5f28d9ec85e40f4cb697bae"
            "000000000000000000000000000000000000000000000000000000000000000d"
            "68656c6c6f2c20776f726c64210000000000000000000000000000000000000"
            "0");
        func.decode(correct);
    }
}
} // namespace abicoder
