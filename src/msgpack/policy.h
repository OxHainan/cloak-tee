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
      // msgpack conversion for Policy
      template <>
      struct convert<evm4ccf::rpcparams::Policy>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, evm4ccf::rpcparams::Policy &v) const
        {
          v.contract = o.via.array.ptr[0].as<std::string>();
          v.states = o.via.array.ptr[1].as<std::vector<evm4ccf::policy::Params>>();
          v.functions = o.via.array.ptr[2].as<std::vector<evm4ccf::policy::Function>>();
          return o;
        }
      };

      template <>
      struct pack<evm4ccf::rpcparams::Policy>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, evm4ccf::rpcparams::Policy const& v) const
        {
          o.pack_array(3);
          o.pack(v.contract);
          o.pack(v.states);
          o.pack(v.functions);
          return o;
        }
      };

        // msgpack conversion for Params
      template <>
      struct convert<evm4ccf::policy::Params>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, evm4ccf::policy::Params &v) const
        {
          v.name = o.via.array.ptr[0].as<std::string>();
          v.type = o.via.array.ptr[1].as<std::string>();
          v.owner = o.via.array.ptr[2].as<std::string>();
          auto value = o.via.array.ptr[3].as<std::string>();
          if (value != "") {
              v.value = value;
          }
          return o;
        }
      };

      template <>
      struct pack<evm4ccf::policy::Params>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, evm4ccf::policy::Params const& v) const
        {
          o.pack_array(4);
          o.pack(v.name);
          o.pack(v.type);
          o.pack(v.owner);
          o.pack(v.value.value_or(""));
          return o;
        }
      };

        // msgpack conversion for Params
      template <>
      struct convert<evm4ccf::policy::Function>
      {
        msgpack::object const& operator()(
            msgpack::object const& o, evm4ccf::policy::Function &v) const
        {
            v.name = o.via.array.ptr[0].as<std::string>();
            v.type = o.via.array.ptr[1].as<std::string>();
            v.inputs = o.via.array.ptr[2].as<std::vector<evm4ccf::policy::Params>>();
            v.read = o.via.array.ptr[3].as<std::vector<evm4ccf::policy::stateParams>>();
            v.mutate = o.via.array.ptr[4].as<std::vector<evm4ccf::policy::stateParams>>();
            v.outputs = o.via.array.ptr[5].as<std::vector<evm4ccf::policy::Params>>();
      
          return o;
        }
      };

      template <>
      struct pack<evm4ccf::policy::Function>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, evm4ccf::policy::Function const& v) const
        {
          o.pack_array(6);
          o.pack(v.name);
          o.pack(v.type);
          o.pack(v.inputs);
          o.pack(v.read);
          o.pack(v.mutate);
          o.pack(v.outputs);
          return o;
        }
      };

       // msgpack conversion for Params
      template <>
      struct convert<evm4ccf::policy::stateParams>
      {
        msgpack::object const& operator()(
            msgpack::object const& o, evm4ccf::policy::stateParams &v) const
        {
            v.name = o.via.array.ptr[0].as<std::string>();
            v.keys = o.via.array.ptr[1].as<std::vector<std::string>>();     
          return o;
        }
      };

      template <>
      struct pack<evm4ccf::policy::stateParams>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, evm4ccf::policy::stateParams const& v) const
        {
          o.pack_array(2);
          o.pack(v.name);
          o.pack(v.keys);

          return o;
        }
      };
    } // namespace adaptor
  } // namespace msgpack
} // namespace msgpack
