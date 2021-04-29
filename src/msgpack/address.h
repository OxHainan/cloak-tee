// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

#include <msgpack/msgpack.hpp>

// To instantiate the kv map types above, all keys and values must be
// convertible to msgpack
namespace msgpack
{
  MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
  {
    namespace adaptor
    {
      // msgpack conversion for uint256_t
      template <>
      struct convert<uint256_t>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, uint256_t& v) const
        {
          const std::vector<uint8_t> vec =
            o.via.array.ptr[0].as<std::vector<uint8_t>>();
          v = eevm::from_big_endian(vec.data(), vec.size());

          return o;
        }
      };

      template <>
      struct pack<uint256_t>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, uint256_t const& v) const
        {
          std::vector<uint8_t> big_end_val(0x20); // size of 256 bits in bytes
          eevm::to_big_endian(v, big_end_val.data());
          o.pack_array(1);
          o.pack(big_end_val);
          return o;
        }
      };

    } // namespace adaptor
  } // namespace msgpack
} // namespace msgpack
