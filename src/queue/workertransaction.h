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
#include "abi/abicoder.h"
#include "app/utils.h"
#include "ccf/crypto/pem.h"
#include "ccf/ds/logger.h"
#include "ccf/tx.h"
#include "crypto/secp256k1/key_pair.h"
#include "ethereum/syncstate.h"
#include "ethereum/tee_manager.h"
#include "ethereum_transaction.h"
#include "fmt/format.h"
#include "map"
#include "string"
#include "types.h"
#include "vector"

#include <eEVM/bigint.h>
#include <eEVM/keccak256.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
namespace evm4ccf
{
    using namespace eevm;
    using namespace rpcparams;
    using ByteData = std::string;
    using Address = eevm::Address;
    using Policy = rpcparams::Policy;
    // using h256 = eevm::KeccakHash;
    using ByteString = std::vector<uint8_t>;

    // tables
    struct PrivacyPolicyTransaction;
    struct CloakPolicyTransaction;
    using Privacys = ccf::ServiceMap<eevm::Keccak256, PrivacyPolicyTransaction>;
    using PrivacyDigests = kv::RawCopySerialisedMap<Address, eevm::Keccak256>;
    using CloakPolicys =
      ccf::ServiceMap<eevm::Keccak256, CloakPolicyTransaction>;
    using CloakDigests = kv::RawCopySerialisedMap<Address, eevm::Keccak256>;
    using StatesDigests =
      kv::RawCopySerialisedMap<eevm::Keccak256, eevm::Keccak256>;
    constexpr size_t GCM_SIZE_IV = 12;

    struct MultiPartyTransaction
    {
        size_t nonce;
        ByteString to;
        Address from;
        ByteString publicKeys;
        policy::MultiPartyParams params;

        bool check_transaction_type()
        {
            if (to.size() == 20u)
                return false;
            if (to.size() == 32u)
                return true;
            throw std::logic_error(fmt::format(
              "Unsupported transaction type, to length should be {} or {}, but "
              "is {}",
              20u,
              32u,
              to.size()));
        }

        ByteData name() const
        {
            return params.name();
        }
    };

    using MultiPartys = kv::Map<eevm::Keccak256, MultiPartyTransaction>;

    struct PrivacyPolicyTransaction
    {
      public:
        Address from;
        Address to;
        Address verifierAddr;
        ByteData codeHash;
        rpcparams::Policy policy;
        PrivacyPolicyTransaction() {}
    };

    DECLARE_JSON_TYPE(PrivacyPolicyTransaction)
    DECLARE_JSON_REQUIRED_FIELDS(
      PrivacyPolicyTransaction, from, to, verifierAddr, codeHash, policy)

    struct CloakPolicyTransaction
    {
      public:
        Address from;
        Address to;
        Address verifierAddr;
        ByteData codeHash;
        policy::Function function;
        std::vector<policy::Params> states;
        std::vector<std::string> old_states;
        std::vector<std::string> requested_addresses;
        std::map<std::string, std::string> public_keys;
        Status status = Status::PENDING;
        std::map<ByteString, std::string> partys;

        CloakPolicyTransaction() {}

        CloakPolicyTransaction(
          const PrivacyPolicyTransaction& ppt, const ByteData& name)
        {
            to = ppt.to;
            verifierAddr = ppt.verifierAddr;
            codeHash = ppt.codeHash;
            states = ppt.policy.states;
            function = ppt.policy.get_funtions(name);
        }

        void set_status(Status status_)
        {
            status = status_;
        }

        Status get_status() const
        {
            return status;
        }

        void set_content(const MultiPartyTransaction& mul)
        {
            for (auto&& [name, value] : mul.params.inputs)
            {
                function.padding(name, value);
            }

            partys[mul.publicKeys] = nlohmann::json(mul.params).dump();
        }

        std::tuple<std::vector<Address>, std::vector<std::string>>
        calcInputsHash() const
        {
            auto party = std::vector<Address>();
            auto inputsHash = std::vector<std::string>();
            for (auto&& [key, value] : partys)
            {
                party.push_back(get_address_from_public_key_asn1(key));
                inputsHash.push_back(eevm::Keccak256(value).hex_str());
            }

            return std::make_tuple(party, inputsHash);
        }

        std::vector<uint8_t> packedPropose(const eevm::Keccak256& txId) const
        {
            auto [partys, inputHash] = calcInputsHash();

            auto encoder = abicoder::Encoder("propose");
            encoder.add_inputs(
              "txId", "uint256", txId.hex_str(), abicoder::number_type());
            encoder.add_inputs(
              "verifierAddr",
              "address",
              verifierAddr,
              abicoder::common_type("address"));
            encoder.add_inputs(
              "partys",
              "address[]",
              partys,
              abicoder::make_common_array("address"));
            encoder.add_inputs(
              "inputHash",
              "bytes32[]",
              inputHash,
              abicoder::make_bytes_array(32));
            encoder.add_inputs(
              "deposit",
              "uint256",
              uint256_t(1000000000),
              abicoder::number_type());
            return encoder.encodeWithSignatrue();
        }

        std::vector<std::string> get_states_read()
        {
            std::vector<std::string> read;
            for (size_t i = 0; i < states.size(); i++)
            {
                auto state = states[i];
                if (state.structural_type["type"] != "mapping")
                {
                    continue;
                }

                read.push_back(to_hex_string_fixed(i));
                auto keys = function.get_mapping_keys(
                  eevm::to_checksum_address(from), state.name);
                read.push_back(
                  to_hex_string_fixed(function.get_keys_size(state.name)));
                read.insert(read.end(), keys.begin(), keys.end());
            }

            LOG_DEBUG_FMT("read:{}", fmt::join(read, ", "));
            return read;
        }

        size_t get_states_return_len(bool encrypted)
        {
            size_t res = 0;
            for (auto&& state : states)
            {
                std::string owner = state.owner["owner"].get<std::string>();
                size_t factor = encrypted && owner != "all" ? 3 : 1;
                if (state.structural_type["type"] == "mapping")
                {
                    size_t depth = state.structural_type["depth"].get<size_t>();
                    size_t keys_size = function.get_keys_size(state.name);
                    res += 2 + (depth + factor) * keys_size;
                }
                else
                {
                    res += factor + 1;
                }
            }
            LOG_DEBUG_FMT("return_len:{}", res);
            return res;
        }

        std::vector<uint8_t> get_states_call_data(bool encrypted)
        {
            std::vector<std::string> read = get_states_read();
            size_t return_len = get_states_return_len(encrypted);
            LOG_DEBUG_FMT(
              "get_states_call_data, return_len:{}, read:{}",
              return_len,
              fmt::join(read, ", "));

            auto encoder = abicoder::Encoder("get_states");
            encoder.add_inputs(
              "read", "bytes[]", read, abicoder::make_bytes_array());
            encoder.add_inputs(
              "return_len",
              "uint256",
              to_hex_string(return_len),
              abicoder::number_type());
            auto data = encoder.encodeWithSignatrue();
            LOG_DEBUG_FMT(
              "encoded:{}", fmt::join(abicoder::split_abi_data(data), "\n"));
            return data;
        }

        bool request_public_keys(
          const eevm::Keccak256& target_digest,
          cloak4ccf::TeeManager::AccountPtr acc,
          Address& service_addr)
        {
            // state => address
            std::map<std::string, std::string> addresses;
            visit_states(
              old_states, true, [this, &addresses](auto id, size_t idx) {
                  if (
                    states[id].structural_type["type"] == "address" &&
                    states[id].owner["owner"] == "all")
                  {
                      addresses[states[id].name] = eevm::to_checksum_address(
                        eevm::to_uint256(old_states[idx + 1]));
                  }
              });

            // get result
            std::vector<std::string> res;
            bool included_tee = false;
            visit_states(
              old_states,
              true,
              [this, &included_tee, &res, &addresses](size_t id, size_t) {
                  auto p = states[id];
                  std::string owner = p.owner["owner"].get<std::string>();
                  if (owner == "all")
                  {
                      return;
                  }
                  else if (owner == "tee")
                  {
                      included_tee = true;
                  }
                  else if (owner == "mapping")
                  {
                      // mapping
                      int key_var_pos = p.owner["var_pos"].get<int>();
                      if (key_var_pos == -1)
                      {
                          res.push_back(
                            addresses.at(p.owner["var"].get<std::string>()));
                      }
                      else
                      {
                          auto keys = function.get_mapping_keys(
                            eevm::to_checksum_address(from),
                            p.name,
                            key_var_pos,
                            false);
                          res.insert(res.end(), keys.begin(), keys.end());
                      }
                  }
                  else
                  {
                      // identifier
                      res.push_back(addresses.at(owner));
                  }
              });

            if (res.empty())
            {
                if (included_tee)
                {
                    old_states = decrypt_states(acc->get_tee_kp());
                }
                return false;
            }

            requested_addresses = res;
            LOG_DEBUG_FMT(
              "requested_addresses:{}", fmt::join(requested_addresses, ", "));

            auto encoder = abicoder::Encoder("getPk");
            encoder.add_inputs(
              "read", "address[]", res, abicoder::make_common_array("address"));
            auto data = encoder.encodeWithSignatrue();

            auto response = Ethereum::SyncStateResponse(
              target_digest, acc->get_address(), service_addr, data);
            Utils::cloak_agent_log("request_public_keys", response);
            return true;
        }

        std::vector<std::string> decrypt_states(
          crypto::secp256k1::KeyPairPtr tee_kp)
        {
            std::vector<std::string> res;
            visit_states(
              old_states, true, [this, &res, &tee_kp](size_t id, size_t idx) {
                  res.push_back(old_states[idx]);
                  auto p = states.at(id);
                  std::string owner = p.owner["owner"].get<std::string>();
                  if (owner == "all")
                  {
                      if (p.structural_type["type"] == "mapping")
                      {
                          auto size = size_t(to_uint256(old_states[idx + 1]));
                          size_t depth =
                            p.structural_type["depth"].get<size_t>();
                          res.insert(
                            res.end(),
                            old_states.begin() + idx + 1,
                            old_states.begin() + idx + 2 + size * (depth + 1));
                      }
                      else
                      {
                          res.push_back(old_states[idx + 1]);
                      }
                  }
                  else if (owner == "mapping")
                  {
                      auto mapping_keys = function.get_mapping_keys(
                        eevm::to_checksum_address(from), p.name);
                      size_t depth = p.structural_type["depth"].get<size_t>();
                      size_t keys_size = function.get_keys_size(p.name);
                      auto it = mapping_keys.begin();
                      res.push_back(old_states[idx + 1]);
                      for (size_t j = 0; j < keys_size; j++)
                      {
                          res.insert(
                            res.end(), it + j * depth, it + (j + 1) * depth);
                          size_t data_pos = idx + 2 + depth + j * (depth + 3);
                          auto sender_addr =
                            to_uint256(old_states[data_pos + 2]);
                          LOG_DEBUG_FMT(
                            "data_pos:{}, sender_addr:{}",
                            data_pos,
                            to_checksum_address(sender_addr));
                          if (sender_addr == 0)
                          {
                              res.push_back(abicoder::ZERO_HEX_STR);
                              continue;
                          }
                          auto pk =
                            public_keys.at(to_checksum_address(sender_addr));
                          auto der = evm4ccf::get_der_from_raw_public_key(
                            eevm::to_bytes(pk));

                          // tag and iv
                          auto&& [tag, iv] = Utils::split_tag_and_iv(
                            to_bytes(old_states[data_pos + 1]));
                          auto data = to_bytes(old_states[data_pos]);
                          LOG_DEBUG_FMT(
                            "decryption, iv:{}, tag:{}, data:{}",
                            to_hex_string(iv),
                            to_hex_string(tag),
                            old_states[data_pos]);
                          data.insert(data.end(), tag.begin(), tag.end());
                          auto decrypted =
                            Utils::decrypt_data(tee_kp, der, iv, data);
                          res.push_back(to_hex_string(decrypted));
                      }
                  }
                  else
                  {
                      // tee and identifier
                      auto sender_addr =
                        to_checksum_address(to_uint256(old_states[idx + 3]));
                      LOG_DEBUG_FMT("sender_addr:{}", sender_addr);
                      if (to_uint256(sender_addr) == 0)
                      {
                          if (p.structural_type["type"] == "array")
                          {
                              size_t array_size =
                                abicoder::get_static_array_size(
                                  p.structural_type);
                              res.push_back(Utils::repeat_hex_string(
                                abicoder::ZERO_HEX_STR, array_size));
                          }
                          else
                          {
                              res.push_back(abicoder::ZERO_HEX_STR);
                          }
                          return;
                      }
                      // tag and iv
                      auto pk_der = p.owner["owner"] == "tee" ?
                        tee_kp->get_public_key() :
                        get_der_from_raw_public_key(
                          eevm::to_bytes(public_keys.at(sender_addr)));

                      auto&& [tag, iv] = Utils::split_tag_and_iv(
                        eevm::to_bytes(old_states[idx + 2]));
                      //   LOG_INFO_FMT("tag:{}, iv:{}", tag, iv);
                      auto data = eevm::to_bytes(old_states[idx + 1]);
                      data.insert(data.end(), tag.begin(), tag.end());
                      auto decrypted =
                        Utils::decrypt_data(tee_kp, pk_der, iv, data);
                      res.push_back(eevm::to_hex_string(decrypted));
                  }
              });

            LOG_DEBUG_FMT(
              "old_states:{}, res:{}",
              fmt::join(old_states, ", "),
              fmt::join(res, ", "));
            return res;
        }

        std::vector<std::string> encrypt_states(
          crypto::secp256k1::KeyPairPtr tee_kp,
          const std::vector<std::string>& new_states)
        {
            // identifier owner addresses
            std::map<std::string, std::string> addresses;
            visit_states(
              new_states, false, [this, &addresses](size_t id, size_t idx) {
                  if (
                    states[id].structural_type["type"] == "address" &&
                    states[id].owner["owner"] == "all")
                  {
                      addresses[states[id].name] = eevm::to_checksum_address(
                        eevm::to_uint256(old_states[idx + 1]));
                  }
              });

            std::vector<std::string> res;
            visit_states(
              new_states,
              false,
              [this, &res, &addresses, &tee_kp, &new_states](
                size_t id, size_t idx) {
                  // policy state
                  auto tee_addr_hex =
                    to_hex_string(get_address_from_public_key(tee_kp));
                  auto ps = states[id];
                  res.push_back(new_states[idx]);
                  LOG_DEBUG_FMT("ps:{}", nlohmann::json(ps).dump());
                  if (ps.owner["owner"] == "all")
                  {
                      if (ps.structural_type["type"] == "mapping")
                      {
                          auto size = eevm::to_uint64(new_states[idx + 1]);
                          size_t depth =
                            ps.structural_type["depth"].get<size_t>();
                          res.insert(
                            res.end(),
                            new_states.begin() + idx + 1,
                            new_states.begin() + idx + 2 + (depth + 1) * size);
                      }
                      else
                      {
                          res.push_back(new_states[idx + 1]);
                      }
                  }
                  else if (ps.owner["owner"] == "mapping")
                  {
                      auto mapping_keys = function.get_mapping_keys(
                        eevm::to_checksum_address(from), ps.name);
                      size_t depth = ps.structural_type["depth"].get<size_t>();
                      size_t keys_size = function.get_keys_size(ps.name);
                      res.push_back(new_states[idx + 1]);
                      auto it = mapping_keys.begin();
                      for (size_t j = 0; j < keys_size; j++)
                      {
                          res.insert(
                            res.end(), it + depth * j, it + depth * (j + 1));
                          auto iv = crypto::secp256k1::create_entropy()->random(
                            GCM_SIZE_IV);
                          auto msg_sender = eevm::to_checksum_address(
                            eevm::to_uint256(mapping_keys[j]));

                          auto der = evm4ccf::get_der_from_raw_public_key(
                            eevm::to_bytes(public_keys.at(msg_sender)));
                          auto&& [encrypted, tag] = Utils::encrypt_data_s(
                            tee_kp,
                            der,
                            iv,
                            to_bytes(new_states[idx + 3 + j * 2]));

                          tag.insert(tag.end(), iv.begin(), iv.end());
                          res.insert(
                            res.end(),
                            {to_hex_string(encrypted),
                             to_hex_string(tag),
                             mapping_keys[j]});
                      }
                  }
                  else
                  {
                      // tee and identifier
                      LOG_DEBUG_FMT("id:{}, owner:{}", id, ps.owner.dump());
                      std::string sender_addr = ps.owner["owner"] == "tee" ?
                        tee_addr_hex :
                        addresses.at(ps.owner["owner"]);

                      auto pk_der = ps.owner["owner"] == "tee" ?
                        tee_kp->get_public_key() :
                        get_der_from_raw_public_key(
                          eevm::to_bytes(public_keys.at(sender_addr)));

                      auto iv = crypto::secp256k1::create_entropy()->random(
                        GCM_SIZE_IV);
                      auto&& [encrypted, tag] = Utils::encrypt_data_s(
                        tee_kp, pk_der, iv, to_bytes(new_states[idx + 1]));
                      tag.insert(tag.end(), iv.begin(), iv.end());
                      res.insert(
                        res.end(),
                        {to_hex_string(encrypted),
                         to_hex_string(tag),
                         sender_addr});
                  }
              });
            return res;
        }

        // f: size_t(the id of states) -> size_t(the index of states) -> void
        void visit_states(
          const std::vector<std::string>& v_states,
          bool is_encryped,
          std::function<void(size_t, size_t)> f)
        {
            for (size_t i = 0; i < v_states.size();)
            {
                size_t id = eevm::to_uint64(v_states[i]);
                f(id, i);
                auto state = states[id];
                int factor =
                  is_encryped && state.owner["owner"] != "all" ? 3 : 1;
                if (state.structural_type["type"] == "mapping")
                {
                    size_t depth = state.structural_type["depth"].get<size_t>();
                    i +=
                      2 + eevm::to_uint64(v_states[i + 1]) * (factor + depth);
                }
                else
                {
                    i += 1 + factor;
                }
            }
        }
    };

    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CloakPolicyTransaction)
    DECLARE_JSON_REQUIRED_FIELDS(
      CloakPolicyTransaction,
      from,
      to,
      verifierAddr,
      codeHash,
      function,
      states,
      old_states,
      requested_addresses,
      public_keys,
      status)
    DECLARE_JSON_OPTIONAL_FIELDS(CloakPolicyTransaction, partys)

} // namespace evm4ccf
