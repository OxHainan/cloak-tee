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

#pragma once
#include "ccf/ds/logger.h"
#include "transaction/exception.h"

namespace evm4ccf
{
    using ByteData = std::string;

    enum class Status
    {
        PENDING,
        REQUESTING_OLD_STATES,
        SYNCING,
        SYNCED,
        SYNC_FAILED,
        DROPPED,
    };

    DECLARE_JSON_ENUM(
      Status,
      {
        {Status::PENDING, "PENDING"},
        {Status::REQUESTING_OLD_STATES, "REQUESTING_OLD_STATES"},
        {Status::SYNCING, "SYNCING"},
        {Status::SYNCED, "SYNCED"},
        {Status::SYNC_FAILED, "SYNC_FAILED"},
        {Status::DROPPED, "DROPPED"},
      })

    struct MPT_CALL
    {
        struct In
        {
            std::string id = {};
        };

        struct Out
        {
            Status status = {};
            std::string output = {};
        };
    };

    DECLARE_JSON_TYPE(MPT_CALL::In)
    DECLARE_JSON_REQUIRED_FIELDS(MPT_CALL::In, id)

    DECLARE_JSON_TYPE(MPT_CALL::Out)
    DECLARE_JSON_REQUIRED_FIELDS(MPT_CALL::Out, status, output)

    namespace policy
    {
        struct MultiPartyParams
        {
            ByteData function;
            std::map<std::string, nlohmann::json> inputs;
            // MSGPACK_DEFINE(function, inputs);

            ByteData name() const
            {
                return function;
            }
        };

        DECLARE_JSON_TYPE(MultiPartyParams)
        DECLARE_JSON_REQUIRED_FIELDS(MultiPartyParams, function, inputs)

        struct Params
        {
          public:
            ByteData name = {};
            nlohmann::json structural_type;
            nlohmann::json owner;
            std::optional<nlohmann::json> value = std::nullopt;

            // MSGPACK_DEFINE(name, structural_type, owner, value);

            nlohmann::json getValue() const
            {
                if (!value.has_value())
                {
                    throw cloak4ccf::Transaction::TransactionException(
                      fmt::format(
                        "multi party transaction has not complete, get [{}] "
                        "has no value",
                        name));
                }

                return value.value();
            }

            void set_value(const nlohmann::json& _v)
            {
                value = _v;
            }
        };

        DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Params)
        DECLARE_JSON_OPTIONAL_FIELDS(Params, name, value)
        DECLARE_JSON_REQUIRED_FIELDS(Params, owner, structural_type)

        struct stateParams
        {
            ByteData name = {};
            std::vector<ByteData> keys = {};
            // MSGPACK_DEFINE(name, keys);
        };

        DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(stateParams)
        DECLARE_JSON_OPTIONAL_FIELDS(stateParams, keys)
        DECLARE_JSON_REQUIRED_FIELDS(stateParams, name)

        struct Function
        {
          public:
            ByteData type;
            ByteData name;
            std::vector<uint8_t> entry;
            std::vector<Params> inputs;
            std::vector<stateParams> read;
            std::vector<stateParams> mutate;
            std::vector<Params> outputs;
            std::vector<uint8_t> raw_outputs;

            std::vector<uint8_t> packed_to_data()
            {
                auto encoder = abicoder::Encoder();
                for (int i = 0; i < inputs.size(); i++)
                {
                    encoder.add_inputs(
                      inputs[i].name,
                      "",
                      inputs[i].getValue(),
                      inputs[i].structural_type);
                }

                return encoder.encode(entry);
            }

            void padding(const std::string& name_, const nlohmann::json& value)
            {
                if (complete())
                    return;

                for (size_t i = 0; i < inputs.size(); i++)
                {
                    if (name_ == inputs[i].name)
                    {
                        inputs[i].set_value(value);
                        return;
                    }
                }

                throw std::logic_error(
                  fmt::format("input params doesn`t match, get {}", name_));
            }

            bool complete() const
            {
                for (auto&& x : inputs)
                {
                    if (!x.value.has_value())
                    {
                        return false;
                    }
                }
                return true;
            }

            std::vector<std::string> get_mapping_keys(
              const std::string& msg_sender,
              const std::string& name,
              int pos = -1,
              bool encoded = true)
            {
                std::vector<std::string> res;
                auto ps = read;
                ps.insert(ps.end(), mutate.begin(), mutate.end());
                LOG_DEBUG_FMT(
                  "get_mapping_keys, msg_sender:{}, name:{}", msg_sender, name);
                for (auto&& x : ps)
                {
                    if (x.name == name)
                    {
                        for (auto&& key : x.keys)
                        {
                            std::vector<std::string> nested_keys =
                              Utils::split_string(key, ':');
                            LOG_DEBUG_FMT(
                              "key:{}, nested_keys:{}",
                              key,
                              fmt::join(nested_keys, ", "));
                            if (pos != -1)
                            {
                                nested_keys = {nested_keys.at(pos)};
                            }
                            for (auto&& single_key : nested_keys)
                            {
                                if (single_key == "msg.sender")
                                {
                                    if (encoded)
                                    {
                                        res.push_back(eevm::to_hex_string(
                                          abicoder::Address(msg_sender)
                                            .encode()));
                                    }
                                    else
                                    {
                                        res.push_back(msg_sender);
                                    }
                                    continue;
                                }
                                for (auto&& input : inputs)
                                {
                                    if (input.name == single_key)
                                    {
                                        if (encoded)
                                        {
                                            auto data =
                                              abicoder::Encoder::encode(
                                                "",
                                                input.value.value(),
                                                input.structural_type);
                                            res.push_back(
                                              eevm::to_hex_string(data));
                                        }
                                        else
                                        {
                                            res.push_back(input.value.value());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return res;
            }

            size_t get_keys_size(const std::string& name)
            {
                auto ps = read;
                ps.insert(ps.end(), mutate.begin(), mutate.end());
                size_t sum = 0;
                for (auto&& x : ps)
                {
                    if (x.name == name)
                    {
                        sum += x.keys.size();
                    }
                }
                return sum;
            }
        };

    } // namespace policy

    namespace rpcparams
    {
        struct Policy
        {
          public:
            ByteData contract = {};
            std::vector<policy::Params> states;
            std::vector<policy::Function> functions;

            // MSGPACK_DEFINE(contract, states, functions);

            policy::Function get_funtions(const ByteData& name) const
            {
                for (int i = 0; i < functions.size(); i++)
                {
                    if (functions[i].name == name)
                    {
                        return functions[i];
                    }
                }

                throw std::logic_error(fmt::format(
                  "doesn't find this {} function in this policy modules",
                  name));
            }
        };

        struct SendPrivacyPolicy
        {
            eevm::Address from = {};
            eevm::Address to = {};
            ByteData codeHash = {};
            eevm::Address verifierAddr = {};
            ByteData policy = {};
        };

        struct SendMultiPartyTransaction
        {
            ByteData params = {};
        };

    } // namespace rpcparams
} // namespace evm4ccf

#include "nljsontypes.h"
// MSGPACK_ADD_ENUM(evm4ccf::Status);
