#pragma once

#include "iostream"
#include "string"
#include "deque"
#include "workertransaction.h"
#include "unordered_map"
#include "../app/tables.h"
namespace evm4ccf
{
    using h256 = eevm::KeccakHash;
    using Address = eevm::Address;
    using Mutex = std::mutex;
    using Guard = std::lock_guard<std::mutex>;
    using RecursiveMutex = std::recursive_mutex;
    using RecursiveGuard = std::lock_guard<std::recursive_mutex>;

    
    
class WorkerQueue
{
public:
   
    WorkerQueue(kv::Store& _store); 
    ~WorkerQueue() {}
    
    h256 addModule( PrivacyPolicyTransaction& tx);
    h256 addMultiParty(MultiPartyTransaction &mp);
    PrivacyPolicyTransaction getPrivacyPolicyTransactionByHash(const h256& hash);
    ByteData getMultiPartyStatus(const h256& hash);
    bool drop(const h256 &hash);
    std::optional<PrivacyPolicyTransaction> findModules(const Address &addr);
    std::optional<CloakTransaction*> GetCloakTransaction(const h256 &hash);
    // void set_consensus(kv::Consensus* &c) {
    //     consensus = c;
    //     if(consensus != nullptr)
    //     cout << "当前节点：" << consensus->is_primary() << endl;
    // }
    // kv::Tx tx;
    
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

    
    // kv::Consensus* consensus;
    tables::TransactionStorage storage;
    kv::Store& store;
    kv::Tx txStorage;
    // mutable Mutex x_queue;      // 验证交易队列锁
    // std::condition_variable m_queueReady;										///< Signaled when m_unverified has a new entry.
    // std::thread verify;
    // std::atomic<bool> m_aborting = {false};
};

} // namespace evm4ccf
