#pragma once

#include "iostream"
#include "string"
#include "deque"
#include "workertransaction.h"
#include "unordered_map"
namespace evm4ccf
{
    using h256 = eevm::KeccakHash;
    using Address = eevm::Address;
class WorkerQueue
{
public:
    WorkerQueue() {}
    
    h256 addModule( PrivacyPolicyTransaction& tx);
    h256 addMultiParty(MultiPartyTransaction &mp);
    PrivacyPolicyTransaction getPrivacyPolicyTransactionByHash(const h256& hash);
    ByteData getMultiPartyStatus(const h256& hash);
    bool drop(const h256 &hash);
    PrivacyPolicyTransaction findModules(const Address &addr);
private:
    h256 addTx(CloakTransaction &ct);
    h256 update(CloakTransaction &ct);
    bool existCloakTx(const Address &addr);
    std::deque<MultiPartyTransaction> pendQueue;    // 等待队列，用来处理已经完成的workerQueue，即将进入交易状态
  // 工作队列，用来收集rpc请求
    std::unordered_map<h256, CloakTransaction> workerQueue;
    std::map<Address, h256> modules;
    std::map<Address, h256> queueTx;
    std::unordered_map<h256, PrivacyPolicyTransaction> privacyPolicy;
};

} // namespace evm4ccf
