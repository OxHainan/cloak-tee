#pragma once

#include "const.h"
#include "kv/tx.h"
#include "tls/key_pair.h"
#include "tls/pem.h"
#include "utils.h"

#include <cstddef>
#include <eEVM/address.h>
#include <eEVM/util.h>
#include <ethereum_transaction.h>
#include <string>

namespace evm4ccf::TeeManager
{
    // global manager
    inline kv::Map<std::string, std::string> tee_manager(Const::TableNames::TEE_MANAGER);

    // names
    using Address = eevm::Address;

    inline void prepare(kv::Tx& tx, Address cloak_service_addr, Address pki_addr) {
        // generate tee kp
        auto handler = tx.get_view(tee_manager);
        auto kp = tls::make_key_pair(tls::CurveImpl::secp256k1_bitcoin);
        if (handler->get(Const::TEE_MANAGER_KEYS::KP_SK).has_value()) {
            LOG_AND_THROW("tee has been prepared");
        }
        handler->put(Const::TEE_MANAGER_KEYS::KP_SK, kp->private_key_pem().str());

        // register tee address
        std::vector<uint8_t> data = Utils::make_function_selector("setTEEAddress()");
        rpcparams::MessageCall mc;
        mc.from = get_addr_from_kp(kp);
        mc.to = cloak_service_addr;
        mc.data = eevm::to_hex_string(data);
        auto signed_data = sign_eth_tx(kp, mc, 0);
        Utils::cloak_agent_log("register_tee_addr", eevm::to_hex_string(signed_data));

        // set pki address
        handler->put(Const::TEE_MANAGER_KEYS::PKI_ADDR, eevm::to_checksum_address(pki_addr));

        // set nonce
        handler->put(Const::TEE_MANAGER_KEYS::NONCE, eevm::to_hex_string(1));
    }

    inline tls::KeyPairPtr get_tee_kp(kv::Tx& tx) {
        auto handler = tx.get_view(tee_manager);
        // get kp
        auto sk_opt = handler->get(Const::TEE_MANAGER_KEYS::KP_SK);
        if (!sk_opt.has_value())
        {
            LOG_AND_THROW("kp_sk not found");
        }
        tls::Pem sk_pem(sk_opt.value());
        return tls::make_key_pair(sk_pem);
    }

    inline size_t get_tee_nonce(kv::Tx& tx) {
        auto handler = tx.get_view(tee_manager);
        // get pki address
        auto nonce_opt = handler->get(Const::TEE_MANAGER_KEYS::NONCE);
        if (!nonce_opt.has_value())
        {
            LOG_AND_THROW("nonce not found");
        }
        return eevm::to_uint64(nonce_opt.value());
    }

    inline Address get_pki_addr(kv::Tx& tx) {
        auto handler = tx.get_view(tee_manager);
        // get pki address
        auto pki_addr_opt = handler->get(Const::TEE_MANAGER_KEYS::PKI_ADDR);
        if (!pki_addr_opt.has_value())
        {
            LOG_AND_THROW("pki address not found");
        }
        return eevm::to_uint256(pki_addr_opt.value());
    }

    inline Address tee_addr(kv::Tx& tx) {
        return get_addr_from_kp(get_tee_kp(tx));
    }

    inline size_t get_and_incr_nonce(kv::Tx &tx) {
        auto handler = tx.get_view(tee_manager);
        // get pki address
        auto nonce_opt = handler->get(Const::TEE_MANAGER_KEYS::NONCE);
        if (!nonce_opt.has_value())
        {
            LOG_AND_THROW("nonce not found");
        }
        size_t nonce = eevm::to_uint64(nonce_opt.value());
        handler->put(Const::TEE_MANAGER_KEYS::NONCE, eevm::to_hex_string(nonce+1));
        return nonce;
    }
} // namespace evm4ccf::TeeManager
