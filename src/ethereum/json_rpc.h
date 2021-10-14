// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#include "jsonrpc.h"
#include "types.h"
namespace Ethereum {
template <class TTag, typename TParams, typename TResult>
struct RpcBuilder {
    using Tag = TTag;
    using Params = TParams;
    using Result = TResult;

    using In = jsonrpc::ProcedureCall<TParams>;
    using Out = jsonrpc::Response<TResult>;

    static constexpr auto name = TTag::name;

    static In make(ccf::SeqNo n = 0) {
        In in;
        in.id = n;
        in.method = TTag::name;
        return in;
    }
};

namespace ethrpc {
struct GetAccountsTag {
    static constexpr auto name = "eth_accounts";
};
using GetAccounts = RpcBuilder<GetAccountsTag, void, std::vector<eevm::Address>>;

struct GetChainIdTag {
    static constexpr auto name = "eth_chainId";
};

using GetChainId = RpcBuilder<GetChainIdTag, void, size_t>;

struct GetGasPriceTag {
    static constexpr auto name = "eth_gasPrice";
};

using GetGasPrice = RpcBuilder<GetGasPriceTag, void, size_t>;

struct GetEstimateGasTag {
    static constexpr auto name = "eth_estimateGas";
};

using GetEstimateGas = RpcBuilder<GetEstimateGasTag, EstimateGas, Result>;

struct GetBalanceTag {
    static constexpr auto name = "eth_getBalance";
};
using GetBalance = RpcBuilder<GetBalanceTag, AddressWithBlock, Balance>;

struct GetCodeTag {
    static constexpr auto name = "eth_getCode";
};
using GetCode = RpcBuilder<GetCodeTag, AddressWithBlock, ByteData>;

struct GetTransactionCountTag {
    static constexpr auto name = "eth_getTransactionCount";
};
using GetTransactionCount = RpcBuilder<GetTransactionCountTag, GetTransactionCount, size_t>;

struct GetTransactionReceiptTag {
    static constexpr auto name = "eth_getTransactionReceipt";
};

using GetTransactionReceipt =
    RpcBuilder<GetTransactionReceiptTag, GetTransactionReceipt, ReceiptResponse>;

struct SendRawTransactionTag {
    static constexpr auto name = "eth_sendRawTransaction";
};
using SendRawTransaction = RpcBuilder<SendRawTransactionTag, SendRawTransaction, TxHash>;

} // namespace ethrpc

} // namespace Ethereum
