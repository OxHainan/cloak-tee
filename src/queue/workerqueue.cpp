#include "workerqueue.hpp"

using namespace evm4ccf;
using namespace std;
using h256 = eevm::KeccakHash;

h256 WorkerQueue::addModule( PrivacyPolicyTransaction& tx) {
    const h256 txHash = tx.hash();
    privacyPolicy[txHash] = tx;
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

h256 WorkerQueue::addMultiParty(MultiPartyTransaction &mpt) {
    auto ppt = findModules(mpt.to);
    if(ppt.codeHash == "") return h256{};
    if (existCloakTx(mpt.to)) {
        auto ct = workerQueue[queueTx[mpt.to]];
        ct.insert(mpt);
        return update(ct);
    }
    // 添加交易
    cout << "添加新交易"<< endl;
    CloakTransaction ct;
    ppt.to_privacyPolicyModules_call(ct, mpt.name());
    ct.insert(mpt);
    return addTx(ct);
}
// 检查交易是否存在
bool WorkerQueue::existCloakTx(const Address &addr) {
    auto md = queueTx.find(addr);
    if(md == queueTx.end()) return false;
    auto tx = workerQueue.find(md->second);
    if(tx == workerQueue.end()) return false;
    return true;
}
// 添加交易
h256 WorkerQueue::addTx(CloakTransaction &ct) {
    auto hash = ct.hash();
    workerQueue[hash] = ct;
    queueTx[ct.to] = hash;
    return hash;
}
// 更新交易
h256 WorkerQueue::update(CloakTransaction &ct) {
    auto hash = ct.hash();
    workerQueue[hash] = ct;
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

ByteData WorkerQueue::getMultiPartyStatus(const h256& hash) {
    auto tx = workerQueue.find(hash);
    if(tx == workerQueue.end()) return "";
    return tx->second.getStatus();
}
