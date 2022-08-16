#pragma once
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#    include "enclave/virtual_host.h"
#else
#    include "ccf_t.h"
#endif

namespace enclave
{
inline uint256_t get_export_state(uint256_t address, uint256_t key)
{
    uint256_t val;
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
    if (export_state && export_state(address, key, &val)) {
        return val;
    }
#else
    bool ret;
    auto err = export_state(&ret, address, key, &val);
    if (err != OE_OK) {
        throw std::runtime_error("enclave failed!!");
    }

    if (ret) {
        return val;
    }

#endif
    throw std::runtime_error("Web3 Client get export_state failed!!");
}
} // namespace enclave