# EVM for CCF

This repository is based on [EVM-for-CCF](https://github.com/microsoft/EVM-for-CCF). It contains a sample application for the Confidential Consortium Framework ([CCF](https://github.com/Microsoft/CCF)) running an Ethereum Virtual Machine ([EVM](https://github.com/Microsoft/eEVM/)).

The app exposes API endpoints based on the [Ethereum JSON RPC](https://github.com/ethereum/wiki/wiki/JSON-RPC) specification (eg - `eth_sendRawTransaction`, `eth_getTransactionReceipt`), so some standard Ethereum tooling can be reused by merely modifying the transport layer to communicate with CCF.

## Contents

| File/folder       | Description                                |
|-------------------|--------------------------------------------|
| `src`             | Source code for the EVM4CCF app            |
| `samples`         | End-to-end tests, driving an EVM4CCF instance with standard web3.py tools|

## Prerequisites

This sample requires an developing environment of CCF's application. Installation of these requirements is described in [CCF's documentation](https://microsoft.github.io/CCF/ccf-0.15.2/quickstart/build_setup.html).

## Setup

```
git clone --recurse-submodules https://github.com/PlyTools/cloak-evm.git
cd cloak-evm
mkdir build
cd build
cmake .. -GNinja -DTARGET=virtual -DCMAKE_BUILD_TYPE=Debug -L
ninja
```

## Running the sample

To run the test case:

```
cd build
/opt/ccf-0.15.2/bin/sandbox.sh -v -p libevm4ccf.virtual.so

export EVM4CCF_HOME=<the path to evm4ccf>
export CONTRACTS_DIR=${EVM4CCF_HOME}//tests/contracts
python3 "${EVM4CCF_HOME}/samples/evmtest_deploy_and_transfer.py"
```

To launch a local instance for manual testing:

```
cd build
/opt/ccf-0.15.2/bin/sandbox.sh -v -p libevm4ccf.virtual.so -d 0
```

User transactions can then be submitted as described in the [CCF documentation](https://microsoft.github.io/CCF/ccf-0.15.2/users/issue_commands.html#issuing-commands), or via [web3.py](https://web3py.readthedocs.io/) with the `CCFProvider` class defined in `samples/provider.py`.

## Key concepts

CCF is a framework for building fault-tolerant, high-performance, fully-confidential distributed services, hosting a user-defined application. In this case the user-defined application is an interpreter for Ethereum bytecode, executing smart contracts entirely inside a [TEE](https://en.wikipedia.org/wiki/Trusted_execution_environment).

This service looks in many ways like a traditional Ethereum node, but has some fundamental differences:
- Consensus is deterministic rather than probabilistic. Since we trust the executing node, we do not need to re-execute on every node or wait for multiple block commits. There is a single transaction history, with no forks.
- There are no local nodes. Users do not run their own node, trusting it with key access and potentially private state. Instead all nodes run inside enclaves, maintaining privacy and guaranteeing execution integrity, regardless of where those enclaves are actually hosted.
- State is confidential, and that confidentiality is entirely controlled by smart contract logic. The app does not produce a public log of all transactions, and it does not reveal the resulting state to all users. The only access to state is by calling methods on smart contracts, where arbitrarily complex and dynamic restrictions can be applied.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
