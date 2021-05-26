#include "workerqueue.hpp"
#include "ds/logger.h"

using namespace evm4ccf;
using namespace std;
using h256 = eevm::KeccakHash;
#pragma GCC diagnostic ignored "-Wunused-private-field"
#pragma GCC diagnostic ignored "-Wreorder"

WorkerQueue::WorkerQueue(kv::Store& _store) :
    store(_store),
    storage {
        tables::TransactionStorage::Privacy("eth.privacyPolicy"),
    },
    txStorage (store.create_tx())
{
    
}

h256 WorkerQueue::addModule( PrivacyPolicyTransaction& tx) {
    const h256 txHash = tx.hash();
    auto view = storage.get_views(txStorage);
    view.privacy->put(txHash, tx);
    modules[tx.to] = txHash;
    cout << "添加一个隐私模型，HASH为：" << tx.to_hex_hash() << endl;
    return txHash;
}
// 删除交易
bool WorkerQueue::drop(const h256& hash) {
    auto t = workerQueue.find(hash);
    if( t == workerQueue.end()) return false;
    cout << "删除一笔交易" << endl;
    workerQueue.erase(t);
    return true;
}

// TODO: check exception
h256 WorkerQueue::addMultiParty(MultiPartyTransaction &mpt) {
    auto ppt = findModules(mpt.to);
    if (!ppt.has_value()) {
        return {};
    }
    ppt.value().checkMptParams(mpt);
    if (existCloakTx(mpt.to)) {
        auto ct = workerQueue[queueTx[mpt.to]];
        ct.insert(mpt);
        return update(ct);
    }

    // 添加交易
    cout << "添加新交易"<< endl;
    CloakTransaction ct;
    ppt.value().to_privacyPolicyModules_call(ct, mpt.name());
    ct.insert(mpt);
    return addTx(ct);
}
// 检查交易是否存在
bool WorkerQueue::existCloakTx(const Address &addr) {
    auto md = queueTx.find(addr);
    if(md == queueTx.end()) {
        LOG_DEBUG_FMT("addr not found in queueTx: {}\n", addr);
        return false;
    }
    auto tx = workerQueue.find(md->second);
    if(tx == workerQueue.end()) {
        LOG_DEBUG_FMT("h256 not found in workerQueue: {}\n", md->second);
        return false;
    }
    return true;
}
// 添加交易
h256 WorkerQueue::addTx(CloakTransaction &ct) {
    auto hash = ct.hash();
    workerQueue[hash] = ct;
    queueTx[ct.from] = hash;
    return hash;
}
// 更新交易
h256 WorkerQueue::update(CloakTransaction &ct) {
    auto hash = ct.hash();
    workerQueue[hash] = ct;
    return hash;
}

std::optional<PrivacyPolicyTransaction> WorkerQueue::findModules(const Address &addr) {
    auto md = modules.find(addr);
    if(md == modules.end()) {
        LOG_INFO_FMT("addr not found in modules: {}", addr);
        return {};
    };
    auto ppt = storage.get_views(txStorage).privacy->get(md->second);
    return ppt.value_or(PrivacyPolicyTransaction{});
}

std::optional<CloakTransaction*> WorkerQueue::GetCloakTransaction(const h256 &hash) {
    if (auto it = workerQueue.find(hash); it != workerQueue.end()) {
        return &it->second;
    }
    return {};
}

PrivacyPolicyTransaction WorkerQueue::getPrivacyPolicyTransactionByHash(const h256& hash){
    auto t = privacyPolicy.find(hash);
    if(t == privacyPolicy.end()) return {};
    return t->second;
}

ByteData WorkerQueue::getMultiPartyStatus(const h256& hash) {
    auto tx = workerQueue.find(hash);
    if(tx == workerQueue.end()) return "";
    return tx->second.getStatus();
}
