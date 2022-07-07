#pragma once
#ifdef CCHOST_SUPPORTS_VIRTUAL
#    include "enclave/virtual_host.h"
#endif
#ifdef CCHOST_SUPPORTS_SGX
#    include "ccf_t.h"
#endif

namespace enclave
{
inline uint256_t get_export_state(uint256_t address, uint256_t key)
{
    uint256_t val;
#ifdef CCHOST_SUPPORTS_VIRTUAL
    if (export_state && export_state(address, key, &val)) {
        return val;
    }
#endif // CCHOST_SUPPORTS_VIRTUAL

#ifdef CCHOST_SUPPORTS_SGX
    bool ret;
    auto err = export_state(&ret, address, key, &val);
    if (err != OE_OK) {
        throw std::runtime_error("enclave failed!!");
    }

    if (ret) {
        return val;
    }

#endif // CCHOST_SUPPORTS_SGX
    throw std::runtime_error("Web3 Client get export_state failed!!");
}
} // namespace enclave