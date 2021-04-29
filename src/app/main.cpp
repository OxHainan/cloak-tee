

#include "tables.h"
#include "rpc_types.h"
#include "../queue/workerqueue.hpp"
#include "../abi/abicoder.h"
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

const nlohmann::json basic_request = {
R"xxx(
    {
		"from": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"codeHash": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"to": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"verifierAddr": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", 
		"policy": "0x7b2266756e6374696f6e73223a5b7b2274797065223a2266756e6374696f6e222c226e616d65223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a226f776e6572222c2274797065223a2261646472657373222c226f776e6572223a22616c6c227d2c7b226e616d65223a22616d6f756e74222c2274797065223a2275696e74323536222c226f776e6572223a22746565227d5d2c2272656164223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226f776e6572225d7d5d2c226d7574617465223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226d73672e73656e646572225d7d2c7b226e616d65223a2272656365697661626c6573222c226b657973223a5b226f776e65723a6d73672e73656e646572225d7d5d2c226f757470757473223a5b7b226e616d65223a22222c2274797065223a2275696e74323536222c226f776e6572223a22616c6c227d5d7d5d2c22636f6e7472616374223a2253756270707070222c22737461746573223a5b7b226e616d65223a2262616c616e636573222c2274797065223a226d617070696e6728616464726573733d3e75696e7432353629222c226f776e6572223a226d617070696e67286164647265737321783d3e75696e74323536407829227d2c7b226e616d65223a2272656365697661626c6573222c2274797065223a226d617070696e6728616464726573733d3e6d617070696e6728616464726573733d3e75696e743235362929222c226f776e6572223a226d617070696e67286164647265737321783d3e6d617070696e6728616464726573733d3e75696e7432353640782929227d5d7d"
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
 constexpr auto k = "key";
 struct Node
 {
  public:
  std::string invalid_key;
  Address v1;
  MSGPACK_DEFINE(invalid_key, v1);
  Node() {}
  Node(std::string &a, Address& b) : invalid_key(a), v1(b) {}
  void serialized(uint8_t* &data, size_t &size) const {
    serialized::write(data,size,invalid_key);
    serialized::write(data,size,v1);
  }

  static Node deserialize(const uint8_t* &data, size_t &size) {
    Node n;
    n.invalid_key = serialized::read<std::string>(data,size);
    n.v1 = serialized::read<Address>(data,size);
    return n;
  }
 };
 
  
void store(Address b) {

  using PolicyModule = kv::Map<std::string, Node>;
  kv::Store st("kv");
  PolicyModule map("public::eth.policy");
  auto tx = st.create_tx();
  auto view = tx.get_view(map);
  std::string a = "sfjjfsj'";
  Node node(a,b);
  view->put(k,node);
  auto v = view->get(k);
  int res = tx.commit();
  cout << v.has_value() <<endl;
  cout << to_hex_string(v->v1) <<endl;
}
int main() {
    // auto d = kv::Consensus::is_primary();
  //  auto nodeID = ccf::NodeState::is_primary();
    // cout << d <<endl;
    using PrivacyPolicy = kv::Map<Address, PrivacyPolicyTransaction>;
    kv::Store st("kv");
    auto tx = st.create_tx();
    PrivacyPolicy map("public::eth.privacy");
    auto view = tx.get_view(map);
     kv::Consensus* consensus(0);
    auto wq = std::make_unique<WorkerQueue>(st);
    
    try
    {
      const auto tc = basic_request.get<rpcparams::SendPrivacyPolicy>();
      
      auto p = nlohmann::json::parse(Utils::HexToBin(tc.policy));

      auto s = p.get<rpcparams::Policy>();
      // 添加隐私模型
      PrivacyPolicyTransaction ppt(tc);
      view->put(tc.from, ppt);
      std::cout << to_checksum_address(tc.from) << std::endl;
      store(tc.from);
      wq->addModule(ppt);
      auto hash = ppt.hash();

      const auto mp = multiParty.get<rpcparams::SendMultiPartyTransaction>();
      MultiPartyTransaction mpt(mp);

      auto result = wq->addMultiParty(mpt);
      cout << to_hex_string( result)  << endl;
      const auto mp1 = multiParty1.get<rpcparams::SendMultiPartyTransaction>();
      MultiPartyTransaction mpt1(mp1);
      auto result1 = wq->addMultiParty(mpt1);
      // cout << to_hex_string( result1)  << endl;
      auto pp = view->get(tc.from);
      if(pp.has_value()) {
        cout << to_hex_string(pp->to) << endl;
      }
    }
    catch(const std::exception& e)
    {
      std::cerr << e.what() << '\n';
    }
    
    return 0;
}