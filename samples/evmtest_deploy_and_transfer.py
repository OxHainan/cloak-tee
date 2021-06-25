import json
import os
import web3

from utils import *
import ccf.clients
import provider
import ccf_network_config as config
import json
from loguru import logger as LOG
import rlp
from eth_hash.auto import keccak as keccak_256
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

def read_evmtest_policy_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/EvmTestPolicy.json")
    with open(file_path, mode='rb') as f:
        file_json = json.load(f)
        print(file_json)
        return web3.Web3.toHex(file_json.encode('utf-8'))

def read_evmtest_params_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(
            f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(
        contracts_dir, "eevmtests/mptParams.json")
    with open(file_path, mode='rb') as f:
        return web3.Web3.toHex(f.read())

def signMpt(private_key, frm, to, data, nonce=1):
    from_int = int(frm, 0)
    to_int = int(to, 0)
    params = rlp.encode([nonce, from_int, to_int, data])
    msg_hash = keccak_256(params)
    signed = web3.eth.Account.signHash(msg_hash, private_key=private_key)
    res = rlp.encode([nonce, from_int, to_int, data, signed.v, signed.r, signed.s]).hex()
    return res

def signPrivacy(private_key, to, verifierAddr, codeHash, policy1):
    params = rlp.encode([to, verifierAddr, codeHash, policy1])
    msg_hash = keccak_256(params)
    print(msg_hash)
    signed = web3.eth.Account.signHash(msg_hash, private_key=private_key)
    print(signed)
    print(signed.v)
    print(signed.r)
    print(signed.s)
    return rlp.encode([to, verifierAddr, codeHash, policy1,  signed.v, signed.r, signed.s]).hex()


policyData="{\"contract\":\"Subppp\",\"functions\":[{\"type\":\"function\",\"name\":\"settleReceivable\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"owner\":\"all\"},{\"name\":\"amount\",\"type\":\"uint256\",\"owner\":\"tee\"}],\"read\":[{\"name\":\"balances\",\"keys\":[\"owner\"]},{\"name\":\"receivables\",\"keys\":[\"owner:msg.sender\"]}],\"mutate\":[{\"name\":\"balances\",\"keys\":[\"msg.sender\"]},{\"name\":\"receivables\",\"keys\":[\"owner:msg.sender\"]}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"owner\":\"all\"}]}],\"states\":[{\"name\":\"balances\",\"type\":\"mapping(address=>uint256)\",\"owner\":\"mapping(address!x=>uint256@x)\"},{\"name\":\"receivables\",\"type\":\"mapping(address=>mapping(address=>uint256))\",\"owner\":\"mapping(address!x=>mapping(address=>uint256@x))\"}]}"
def test_deploy(ccf_client):
    math_abi, math_bin = read_math_library_from_file()
    evmtest_abi, evmtest_bin = read_evmtest_contract_from_file()

    w3 = web3.Web3(provider.CCFProvider(ccf_client))

    owner = Caller(web3.Account.create(), w3)

    # LOG.info("Library deployment")
    LOG.info(f"owner account:{owner.account.address}")
    # math_spec = w3.eth.contract(abi=math_abi, bytecode=math_bin)

    # # deploy_receipt = owner.sendPrivacyPolicy(math_spec.constructor(), evmtest_policy)

    # deploy_receipt = owner.send_signed(math_spec.constructor())
    # ccf_client.math_library_address = deploy_receipt.contractAddress
    # LOG.info("math_library_address: " + ccf_client.math_library_address)

    # _ph = w3.toHex(w3.sha3(text="EvmTest.sol:Math"))

    # LOG.info("math_library_placeholder: " + "__$"+_ph[2:36] + "$__")

    # LOG.info("Contract deployment")

    # evmtest_bin = evmtest_bin.replace(
    #     "__$"+_ph[2:36] + "$__", ccf_client.math_library_address[2:])

    # evmtest_spec = w3.eth.contract(abi=evmtest_abi, bytecode=evmtest_bin)
    # deploy_receipt = owner.send_signed(
    #     evmtest_spec.constructor(10000, [11, 12, 13]))

    evmtest_policy = read_evmtest_policy_from_file()
    print(evmtest_policy)
    # sppr = owner.sendPrivacyPolicy_v2(owner.account.address, deploy_receipt.contractAddress, "", evmtest_policy)
    # mpt_data = read_evmtest_params_from_file()
    # mpt_params = signMpt(owner.account.key, owner.account.address, deploy_receipt.contractAddress, mpt_data)
    # smptr = owner.sendMultiPartyTransaction(mpt_params)
    policy = signPrivacy(owner.account.key, owner.account.address, owner.account.address, owner.account.address, evmtest_policy)
    # ccf_client.evmtest_contract_address = deploy_receipt.contractAddress
    # print(deploy_receipt.contractAddress)
    print(policy)
    print(policyData)
    # ccf_client.owner_account = owner.account

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

def get_balance(ccf_client):
    w3 = web3.Web3(provider.CCFProvider(ccf_client))
    owner = Caller(web3.Account.create(), w3)
    alice = Caller(web3.Account.create(), w3)
    balance = w3.eth.getBalance(owner.account.address)
    balance1 = w3.eth.getBalance(alice.account.address)
    print(balance)
    print(balance1)
    params = {}
    params['to'] = alice.account.address
    params['from'] = owner.account.address
    params['gas'] = 0
    params['value'] = w3.toWei(18, "ether")
    txhash = w3.eth.sendTransaction(params)
    balance1 = w3.eth.getBalance(alice.account.address)
    count = w3.eth.getTransactionCount('0x03901A8132E3Ac1a32e9eE9fC520A53152DF0A40')
    receipt = w3.eth.getTransactionReceipt(txhash.hex())
    # text = json.loads(receipt)
    # print(receipt)
    print(f"count:{count}")
    print(balance)
    chaind = w3.eth.estimateGas(params)
    print(chaind)

if __name__ == "__main__":

    ccf_client = ccf.clients.CCFClient(
        config.host, 
        config.port, 
        config.ca, 
        config.cert, 
        config.key
        )
    # get_balance(ccf_client)
    test_deploy(ccf_client)
    # test_get_sum(ccf_client)
