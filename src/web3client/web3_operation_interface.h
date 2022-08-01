#pragma once
#include "ccf/node_subsystem_interface.h"
#include "eEVM/bigint.h"
#include "types.h"

#include <vector>
namespace cloak4ccf
{

using RequestData = std::vector<uint8_t>;
using ResponseData = std::vector<uint8_t>;
enum class Methods
{
    ETH_CALL,
    GetBalance,
    GetCode,
    GetTransactionReceipt,
};

enum class EscrowStatus
{
    GETCODE,
    GETPROOF,
};

class AbstractWeb3Operation : public ccf::AbstractNodeSubSystem
{
 public:
    virtual ~AbstractWeb3Operation() = default;
    static char const* get_subsystem_name()
    {
        return "Web3";
    }

    virtual void contract_escrow(const uint256_t&) = 0;
    virtual void set_ethereum_configuration(const EthereumConfiguration) = 0;
};
} // namespace cloak4ccf