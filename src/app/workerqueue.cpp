#include "workerqueue.h"

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

std::tuple<bool, uint8_t> WorkerQueue::addMultiParty(MultiPartyTransaction &mpt) {
    auto md = modules.find(mpt.to);
    if(md == modules.end()) std::make_tuple(false,FAILED);    //未注册此模型
    auto ppt = privacyPolicy.find(md->second);     // 取出模型
    if(ppt==privacyPolicy.end()) return std::make_tuple(false,FAILED);
    
    // // 添加交易
    CloakTransaction ct;
    ppt->second.to_privacyPolicyModules_call(ct, mpt.name());
    ct.insert(mpt);
    auto result = addTx(md->second, ct);
    return std::make_tuple(result, ct.getStatus());
}

bool WorkerQueue::addTx(h256 txHash, CloakTransaction &ct) {
    workerQueue[txHash] = ct;
    return true;
}

PrivacyPolicyTransaction WorkerQueue::getPrivacyPolicyTransactionByHash(const h256& hash){
    auto t = privacyPolicy.find(hash);
    if(t == privacyPolicy.end()) return {};
    return t->second;
}
