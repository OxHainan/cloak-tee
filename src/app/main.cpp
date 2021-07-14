

#include "tables.h"
#include "rpc_types.h"
#include "../abi/abicoder.h"
#include "../transaction/tables.h"

using namespace ccf;
using namespace evm4ccf;
using namespace std;
using namespace eevm;
using namespace abicoder;

template <typename T>
nlohmann::json json_with(
  const nlohmann::json& j, const std::string& field, T&& v)
{
  nlohmann::json result = j;
  result[field] = v;
  return result;
}

nlohmann::json json_without(const nlohmann::json& j, const std::string& field)
{
  nlohmann::json result = j;
  result.erase(field);
  return result;
}
const std::string raw_hex = "0xf9033294de0b295669a9fd93d5f28d9ec85e40f4cb697bae94de0b295669a9fd93d5f28d9ec85e40f4cb697bae94de0b295669a9fd93d5f28d9ec85e40f4cb697baeb902ad7b22636f6e7472616374223a22537562707070222c2266756e6374696f6e73223a5b7b2274797065223a2266756e6374696f6e222c226e616d65223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a226f776e6572222c2274797065223a2261646472657373222c226f776e6572223a22616c6c227d2c7b226e616d65223a22616d6f756e74222c2274797065223a2275696e74323536222c226f776e6572223a22746565227d5d2c2272656164223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226f776e6572225d7d2c7b226e616d65223a2272656365697661626c6573222c226b657973223a5b226f776e65723a6d73672e73656e646572225d7d5d2c226d7574617465223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226d73672e73656e646572225d7d2c7b226e616d65223a2272656365697661626c6573222c226b657973223a5b226f776e65723a6d73672e73656e646572225d7d5d2c226f757470757473223a5b7b226e616d65223a22222c2274797065223a2275696e74323536222c226f776e6572223a22616c6c227d5d7d5d2c22737461746573223a5b7b226e616d65223a2262616c616e636573222c2274797065223a226d617070696e6728616464726573733d3e75696e7432353629222c226f776e6572223a226d617070696e67286164647265737321783d3e75696e74323536407829227d2c7b226e616d65223a2272656365697661626c6573222c2274797065223a226d617070696e6728616464726573733d3e6d617070696e6728616464726573733d3e75696e743235362929222c226f776e6572223a226d617070696e67286164647265737321783d3e6d617070696e6728616464726573733d3e75696e7432353640782929227d5d7d25a0e139c367083b891efb030717c6cb68a576d74de87e8ff528704662f93beb14d6a040c1751aa094acd710d4be557ddc96d5e8390b5ddb13aaea38fa9bc3e62b3781";
const auto multi_hex = "0xf8c98094de0b295669a9fd93d5f28d9ec85e40f4cb697baeb86e7b2266756e6374696f6e223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a226f776e6572222c2276616c7565223a223078313233227d2c7b226e616d65223a22616d6f756e74222c2276616c7565223a22307834353638227d5d7d25a058b73dc66118f8f98836d228078fa6236e3ccb98d9afb63c69889002b062407ba06b39721c1787d6339ec4525e11bbf49699230e44a891ae349ea7d2abcd2b2b53";
const auto multi1_hex = "0xf8cb8094de0b295669a9fd93d5f28d9ec85e40f4cb697baeb8707b2266756e6374696f6e223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a226f776e6572222c2276616c7565223a22307844324639313834313346323033443538663562643733374343416664374234363133346437343233227d5d7d26a0b060213222a97e71199eb177d662b48eb2f413d42d48ad45c2f7cb4c719b63f1a00c796dd35d0289cded64431b14825f5aa27f8b778a0602b7389ce5b841a6e560";

const nlohmann::json basic_request = {
R"xxx(
    {
		"from": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"codeHash": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"to": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"verifierAddr": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", 
		"policy": "0x7b22636f6e7472616374223a22537562707070222c2266756e6374696f6e73223a5b7b2274797065223a2266756e6374696f6e222c226e616d65223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a226f776e6572222c2274797065223a2261646472657373222c226f776e6572223a22616c6c227d2c7b226e616d65223a22616d6f756e74222c2274797065223a2275696e74323536222c226f776e6572223a22746565227d5d2c2272656164223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226f776e6572225d7d2c7b226e616d65223a2272656365697661626c6573222c226b657973223a5b226f776e65723a6d73672e73656e646572225d7d5d2c226d7574617465223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226d73672e73656e646572225d7d2c7b226e616d65223a2272656365697661626c6573222c226b657973223a5b226f776e65723a6d73672e73656e646572225d7d5d2c226f757470757473223a5b7b226e616d65223a22222c2274797065223a2275696e74323536222c226f776e6572223a22616c6c227d5d7d5d2c22737461746573223a5b7b226e616d65223a2262616c616e636573222c2274797065223a226d617070696e6728616464726573733d3e75696e7432353629222c226f776e6572223a226d617070696e67286164647265737321783d3e75696e74323536407829227d2c7b226e616d65223a2272656365697661626c6573222c2274797065223a226d617070696e6728616464726573733d3e6d617070696e6728616464726573733d3e75696e743235362929222c226f776e6572223a226d617070696e67286164647265737321783d3e6d617070696e6728616464726573733d3e75696e7432353640782929227d5d7d"
    }
  )xxx"_json
};
const nlohmann::json multiParty = {
R"xxx(
    {
		"from": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"to": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"params": "0x7b2266756e6374696f6e223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a22616d6f756e74222c2276616c7565223a223078313234227d5d7d"
    }
  )xxx"_json
};
const nlohmann::json multiParty1 = {
R"xxx(
    {
		"from": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"to": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"params": "0x7b2266756e6374696f6e223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a226f776e6572222c2276616c7565223a22307844324639313834313346323033443538663562643733374343416664374234363133346437343233227d5d7d"
    }
  )xxx"_json
};
#include "tls/key_pair.h"
#include "ethereum_transaction.h"
#include "../transaction/generator.h"
int main() {
    const auto raw_tx = eevm::to_bytes(raw_hex);
    // const auto decoded = PrivacyTransactionWithSignature(raw_tx);
    // PrivacyPolicyTransaction tc;
    // auto hash = decoded.to_transaction_call(tc);
    // cout << eevm::to_hex_string(decoded.to_be_signed()) << endl;
    // cout << eevm::to_hex_string(hash) << endl;
    // // cout << eevm::to_hex_string(decoded.data) << endl;
    // cout << eevm::to_hex_string(tc.from) << endl;
    // cout << decoded.codeHash << endl;
    kv::Store st("kv");
    TransactionTables networks(st);
    
    auto tx = st.create_tx();
    TransactionGenerator gen(networks, tx);
    gen.add_privacy(raw_tx);

    const auto raw1_tx = eevm::to_bytes(multi_hex);
    const auto raw2_tx = eevm::to_bytes(multi1_hex);
    gen.add_cloakTransaction(raw1_tx);
    // gen.add_cloakTransaction(raw1_tx);
    gen.add_cloakTransaction(raw2_tx);

    // const auto decoded = CloakTransactionWithSignature(raw1_tx);
    // MultiPartyTransaction mpt;
    // decoded.to_transaction_call(mpt);
    // cout << eevm::to_hex_string(decoded.digest()) << endl;

    return 0;
}