import json
import os
import web3

from utils import *
import ccf.clients
import provider
import ccf_network_config as config

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


def test_deploy(ccf_client):
    math_abi, math_bin = read_math_library_from_file()
    evmtest_abi, evmtest_bin = read_evmtest_contract_from_file()

    w3 = web3.Web3(provider.CCFProvider(ccf_client))

    owner = Caller(web3.Account.create(), w3)

    LOG.info("Library deployment")
    math_spec = w3.eth.contract(abi=math_abi, bytecode=math_bin)

    # deploy_receipt = owner.sendPrivacyPolicy(math_spec.constructor())

    deploy_receipt = owner.send_signed(math_spec.constructor())
    ccf_client.math_library_address = deploy_receipt.contractAddress
    LOG.info("math_library_address: " + ccf_client.math_library_address)

    _ph = w3.toHex(w3.sha3(text="EvmTest.sol:Math"))

    LOG.info("math_library_placeholder: " + "__$"+_ph[2:36] + "$__")

    LOG.info("Contract deployment")

    evmtest_bin = evmtest_bin.replace(
        "__$"+_ph[2:36] + "$__", ccf_client.math_library_address[2:])

    evmtest_spec = w3.eth.contract(abi=evmtest_abi, bytecode=evmtest_bin)
    deploy_receipt = owner.send_signed(
        evmtest_spec.constructor(10000, [11, 12, 13]))

    ccf_client.evmtest_contract_address = deploy_receipt.contractAddress
    ccf_client.owner_account = owner.account

    return ccf_client


def test_get_sum(ccf_client):
    evmtest_abi, evmtest_bin = read_evmtest_contract_from_file()

    LOG.info(f"ccf_client: {ccf_client.name}")
    w3 = web3.Web3(provider.CCFProvider(ccf_client))

    evmtest_contract = EvmTestContract(
        w3.eth.contract(abi=evmtest_abi,
                        address=ccf_client.evmtest_contract_address)
    )

    owner = Caller(ccf_client.owner_account, w3)

    LOG.info("Call getSum of EvmTest")
    LOG.info(evmtest_contract.get_sum(owner, 11, 22))
    assert evmtest_contract.get_sum(owner, 11, 22) == 33



if __name__ == "__main__":

    ccf_client = ccf.clients.CCFClient(
        config.host, 
        config.port, 
        config.ca, 
        config.cert, 
        config.key
        )
    
    test_deploy(ccf_client)
    test_get_sum(ccf_client)