#pragma once

#include "iostream"
#include "string"
#include "deque"
#include "workertransaction.h"
#include "unordered_map"
namespace evm4ccf
{
    using h256 = eevm::KeccakHash;
class WorkerQueue
{
public:
    WorkerQueue() {}
    std::deque<PrivacyPolicyTransaction> pendQueue;    // 等待队列，用来处理已经完成的workerQueue，即将进入交易状态
  // 工作队列，用来收集rpc请求
    std::unordered_map<h256, PrivacyPolicyTransaction> workerQueue;
    void add( PrivacyPolicyTransaction& tx);
    std::tuple<bool, uint8_t> addMultiParty(MultiPartyTransaction &mp);
    PrivacyPolicyTransaction getPrivacyPolicyTransactionByHash(const h256& hash);
    bool drop(const h256 &hash);
};
} // namespace evm4ccf
