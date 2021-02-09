#include "workerqueue.hpp"

using namespace evm4ccf;
using namespace std;
using h256 = eevm::KeccakHash;

void WorkerQueue::addModule( PrivacyPolicyTransaction& tx) {
    const h256 txHash = tx.hash();
    privacyPolicy[txHash] = tx;
    modules[tx.to] = txHash;
    cout << "添加一个隐私模型，HASH为：" << tx.to_hex_hash() << endl;
}

// bool WorkerQueue::drop(const h256& hash) {
//     auto t = workerQueue.find(hash);
//     if( t == workerQueue.end()) return false;
//     // cout << "删除一笔交易，HASH为:" << t->second.to_hex_hash() << endl;
//     workerQueue.erase(t);
//     return true;
// }

h256 WorkerQueue::addMultiParty(MultiPartyTransaction &mpt) {
    auto ppt = findModules(mpt.to);
    if(ppt.codeHash == "") return h256{};
    // 添加交易
    CloakTransaction ct;
    ppt.to_privacyPolicyModules_call(ct, mpt.name());
    ct.insert(mpt);
    return addTx(ct);
}

h256 WorkerQueue::addTx(CloakTransaction &ct) {
    auto hash = ct.hash();
    workerQueue[hash] = std::move(ct);
    return hash;
}

PrivacyPolicyTransaction WorkerQueue::findModules(const Address &addr) {
    auto md = modules.find(addr);
    if(md == modules.end()) return {};
    auto ppt = privacyPolicy.find(md->second);     // 取出模型
    if(ppt==privacyPolicy.end()) return {};
    return ppt->second;
}

PrivacyPolicyTransaction WorkerQueue::getPrivacyPolicyTransactionByHash(const h256& hash){
    auto t = privacyPolicy.find(hash);
    if(t == privacyPolicy.end()) return {};
    return t->second;
}
