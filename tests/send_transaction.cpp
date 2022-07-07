#include "blit.h"
#include "ccf/ds/logger.h"
#include "crypto/secp256k1/key_pair.h"
#include "eEVM/util.h"
#include "ethereum/execute_transaction.h"
#include "ethereum/state.h"
#include "ethereum_transaction.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"

#include <doctest/doctest.h>
#include <fstream>

namespace Ethereum
{
void append_argument(std::vector<uint8_t>& code, const uint256_t& arg)
{
    const auto pre_size = code.size();
    code.resize(pre_size + 32u);
    eevm::to_big_endian(arg, code.data() + pre_size);
}

struct Environment
{
    nlohmann::json contract_definition;
    eevm::Address owner_address;
    eevm::Address contract_address;
};

Environment env;
kv::Store store;
tables::AccountsState acc_state;

TEST_CASE("serialised state encryption")
{
    logger::config::add_text_console_logger();
    store.set_encryptor(std::make_shared<kv::NullTxEncryptor>());
    auto tx = store.create_tx();
    auto es = EthereumState::make_state(tx, acc_state);
    auto peer3_kp =
        std::make_shared<crypto::KeyPair_k1Bitcoin>(crypto::CurveID::SECP256K1);
    env.owner_address = evm4ccf::get_address_from_public_key(peer3_kp);
    const auto contract_path = "../tests/contracts/test_combined.json";
    std::ifstream contract_fstream(contract_path);
    if (!contract_fstream) {
        throw std::runtime_error(fmt::format(
            "Unable to open contract definition file {}", contract_path));
    }

    const auto contracts_definition = nlohmann::json::parse(contract_fstream);
    env.contract_definition = contracts_definition["contracts"];
    MessageCall mc;
    mc.from = env.owner_address;
    mc.data = env.contract_definition["bin"];
    auto result = Ethereum::EVMC(mc, es).run_with_result();
    {
        // verify contract address
        auto to = eevm::generate_address(env.owner_address, 0);
        auto state = es.get(to);
        REQUIRE(state.acc.has_code());
        env.contract_address = to;
    }
    {
        auto function_call =
            eevm::to_bytes(env.contract_definition["hashes"]["set(uint256)"]);
        append_argument(function_call, 100);

        MessageCall mc(env.owner_address, env.contract_address, function_call);
        auto result = Ethereum::EVMC(mc, es).run_with_result();
    }

    auto cl = tx.rw(acc_state.levels);
    cl->put(env.contract_address, ContractLevel::SOLIDITY);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
}

TEST_CASE("send a set transaction")
{
    auto tx = store.create_tx();
    auto es = EthereumState::make_state(tx, acc_state);

    {
        auto function_call =
            eevm::to_bytes(env.contract_definition["hashes"]["set(uint256)"]);
        append_argument(function_call, 100);

        MessageCall mc(env.owner_address, env.contract_address, function_call);
        auto result = Ethereum::EVMC(mc, es).run_with_result();
    }

    {
        auto function_call =
            eevm::to_bytes(env.contract_definition["hashes"]["get()"]);

        MessageCall mc(env.owner_address, env.contract_address, function_call);
        auto result = Ethereum::EVMC(mc, es).run_with_result();
        CHECK(eevm::from_big_endian(result.output.data()) == 200);
    }
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
}

TEST_CASE("Test contract enhanced")
{
    auto tx = store.create_tx();
    auto es = EthereumState::make_state(tx, acc_state);
    auto cl = tx.rw(acc_state.levels);
    auto ch = tx.rw(acc_state.encrypted);
    cl->put(env.contract_address, ContractLevel::SOLIDITY_ENHANCE);
    ch->put(env.contract_address, crypto::create_entropy()->random(32u));

    {
        auto function_call =
            eevm::to_bytes(env.contract_definition["hashes"]["set(uint256)"]);
        append_argument(function_call, 100);

        MessageCall mc(env.owner_address, env.contract_address, function_call);
        auto result = Ethereum::EVMC(mc, es).run_with_result();
    }

    {
        auto function_call =
            eevm::to_bytes(env.contract_definition["hashes"]["get()"]);

        MessageCall mc(env.owner_address, env.contract_address, function_call);
        auto result = Ethereum::EVMC(mc, es).run_with_result();
        CHECK(eevm::from_big_endian(result.output.data()) == 300);
    }
}
} // namespace Ethereum
