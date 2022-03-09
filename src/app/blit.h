#pragma once
#include "eEVM/keccak256.h"
#include "service/blit.h"

#include <eEVM/bigint.h>
#include <eEVM/util.h>
namespace kv::serialisers
{
    template <>
    struct BlitSerialiser<uint256_t>
    {
        static SerialisedEntry to_serialised(const uint256_t& v)
        {
            std::vector<uint8_t> big_end_val(0x20); // size of 256 bits in bytes
            eevm::to_big_endian(v, big_end_val.data());
            return SerialisedEntry(big_end_val.begin(), big_end_val.end());
        };

        static uint256_t from_serialised(const SerialisedEntry& v)
        {
            return eevm::from_big_endian(v.data(), v.size());
        }
    };

    template <>
    struct BlitSerialiser<eevm::Keccak256>
    {
        static SerialisedEntry to_serialised(const eevm::Keccak256& digest)
        {
            auto hex_str = digest.hex_str();
            return SerialisedEntry(hex_str.begin(), hex_str.end());
        }

        static eevm::Keccak256 from_serialised(const SerialisedEntry& data)
        {
            return eevm::Keccak256::from_hex(
              std::string(data.data(), data.end()));
        }
    };
} // namespace kv::serialisers