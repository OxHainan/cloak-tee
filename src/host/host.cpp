#include <web3client/client.h>
#ifdef CCHOST_SUPPORTS_SGX
#    include <ccf_u.h>
#endif

bool export_state(uint256_t contract_address, uint256_t key, uint256_t* value)
{
    auto client = jsonrpc::ws::Client::get_instance();
    std::promise<uint256_t> p;
    auto f = p.get_future();
    client->jsonrpc()->send<jsonrpc::ws::EthGetStorageAt>(
        {contract_address, key}, [&p](jsonrpc::ws::Error::Ptr err, std::shared_ptr<std::vector<uint8_t>> _result) {
            if (err && err->errorCode() != 0) {
                return;
            }

            p.set_value(jsonrpc::ws::EthGetStorageAt::ResultSerialiser::from_serialised(*_result));
        });
    *value = f.get();
    return true;
}
