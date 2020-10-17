# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
import json
import os
import web3

from utils import *
import e2e_args
import infra.ccf
import provider

from loguru import logger as LOG


class EvmTestContract:
    def __init__(self, contract):
        self.contract = contract

    def get_sum(self, caller, test_a, test_b):
        return caller.call(self.contract.functions.getSum(test_a, test_b))


def read_evmtest_contract_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/EvmTest_combined.json")
    return read_contract_from_file(file_path, "EvmTest.sol:EvmTest")


def read_math_library_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/EvmTest_combined.json")
    return read_contract_from_file(file_path, "EvmTest.sol:Math")


def test_deploy(network, args):
    math_abi, math_bin = read_math_library_from_file()
    evmtest_abi, evmtest_bin = read_evmtest_contract_from_file()
    primary, term = network.find_primary()

    with primary.user_client(format="json") as ccf_client:
        w3 = web3.Web3(provider.CCFProvider(ccf_client))

        owner = Caller(web3.Account.create(), w3)

        LOG.info("Library deployment")
        math_spec = w3.eth.contract(abi=math_abi, bytecode=math_bin)
        deploy_receipt = owner.send_signed(math_spec.constructor())
        network.math_library_address = deploy_receipt.contractAddress
        LOG.info("math_library_address: " + network.math_library_address)

        _ph = w3.toHex(w3.sha3(text="EvmTest.sol:Math"))

        LOG.info("math_library_placeholder: " + "__$"+_ph[2:36] + "$__")

        LOG.info("Contract deployment")

        evmtest_bin = evmtest_bin.replace(
            "__$"+_ph[2:36] + "$__", network.math_library_address[2:])

        evmtest_spec = w3.eth.contract(abi=evmtest_abi, bytecode=evmtest_bin)
        deploy_receipt = owner.send_signed(
            evmtest_spec.constructor(10000, [11, 12, 13]))

        network.evmtest_contract_address = deploy_receipt.contractAddress
        network.owner_account = owner.account

    return network


def test_get_sum(network, args):
    evmtest_abi, evmtest_bin = read_evmtest_contract_from_file()
    primary, term = network.find_primary()

    with primary.user_client(format="json") as ccf_client:
        LOG.info(f"ccf_client: {ccf_client.name}")
        w3 = web3.Web3(provider.CCFProvider(ccf_client))

        evmtest_contract = EvmTestContract(
            w3.eth.contract(abi=evmtest_abi,
                            address=network.evmtest_contract_address)
        )

        owner = Caller(network.owner_account, w3)

        LOG.info("Call getSum of EvmTest")
        LOG.info(evmtest_contract.get_sum(owner, 11, 22))
        assert evmtest_contract.get_sum(owner, 11, 22) == 33

    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        network = test_deploy(network, args)
        network = test_get_sum(network, args)


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = "libevm4ccf"

    run(args)
