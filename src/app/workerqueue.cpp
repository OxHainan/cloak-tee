#include "workerqueue.h"

using namespace evm4ccf;
using namespace std;
using h256 = eevm::KeccakHash;

void WorkerQueue::add( PrivacyPolicyTransaction& tx) {
    const h256 txHash = tx.hash();
    workerQueue[txHash] = tx;
    cout << "收到一笔交易，HASH为：" << tx.to_hex_hash() << endl;
}

bool WorkerQueue::drop(const h256& hash) {
    auto t = workerQueue.find(hash);
    if( t == workerQueue.end()) return false;
    cout << "删除一笔交易，HASH为:" << t->second.to_hex_hash() << endl;
    workerQueue.erase(t);
    return true;
}

std::tuple<bool, uint8_t> WorkerQueue::addMultiParty(MultiPartyTransaction &mpt) {
    cout << "多方添加交易，HASH为:" << to_hex_string(mpt.hash()) << endl;
    auto ppt = workerQueue.find(mpt.hash());
    if(ppt==workerQueue.end()) return std::make_tuple(false,FAILED);
    auto [result, data] = ppt->second.insertMultiParty(mpt);
    if(!data.empty())
        std::cout << data << std::endl;
    return std::make_tuple(result,ppt->second.getStatus());
}

PrivacyPolicyTransaction WorkerQueue::getPrivacyPolicyTransactionByHash(const h256& hash){
    auto t = workerQueue.find(hash);
    if(t == workerQueue.end()) return {};
    return t->second;
}
