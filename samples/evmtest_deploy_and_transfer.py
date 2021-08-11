import json
import os
import web3
import time

from utils import *
import ccf.clients
import provider
import ccf_network_config as config
import json
from loguru import logger as LOG
import rlp
from eth_hash.auto import keccak as keccak_256
import subprocess

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

def signMpt(private_key, to, data, nonce=1):
    params = rlp.encode([nonce, to, data])
    msg_hash = keccak_256(params)
    signed = web3.eth.Account.signHash(msg_hash, private_key=private_key)
    res = rlp.encode([nonce, to, data, signed.v, signed.r, signed.s]).hex()
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

def read_transfer_mpt_data(to: str) -> str:
    return f"""
    {{
        "function": "transfer",
        "inputs" : [
            {{"name": "to", "value": "{to}"}},
            {{"name": "value", "value": "10"}}
        ]
    }}
    """

def read_deposit_mpt_data() -> str:
    return f"""
    {{
        "function": "deposit",
        "inputs" : [
            {{"name": "value", "value": "10"}}
        ]
    }}
    """

def read_multiPartyTransfer_mpt_data(to: str) -> str:
    v1 = f"""
    {{
        "function": "multiPartyTransfer",
        "inputs" : [
            {{"name": "value", "value": "10"}}
        ]
    }}
    """
    v2 = f"""
    {{
        "function": "multiPartyTransfer",
        "inputs" : [
            {{"name": "to", "value": "{to}"}}
        ]
    }}
    """
    return v1, v2

def cloak_prepare(ccf_client: ccf.clients.CCFClient, cloak_service_addr: str, pki_addr: str):
    ccf_client.call("/app/cloak_prepare", {"cloak_service_addr": cloak_service_addr, "pki_addr": pki_addr})

def get_pk_pem(key: str) -> str:
    cmd = f"echo 302e0201010420 {key[2:]} a00706052b8104000a | xxd -r -p | openssl ec -inform d -pubout"
    print(f"cmd:{cmd}")
    # exit(1)
    out, err = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
    print(f"key:{key}, out:{out}, err:{err}, pem:{out}")
    return out.decode()

def register_pki(owner: Caller):
    w3 = web3.Web3(web3.Web3.HTTPProvider('http://127.0.0.1:8545'))
    acc = web3.Account.from_key(owner.account.key)
    # w3.eth.default_account = acc.address

    file_name = "CloakPKI.sol"
    file_path = f"{os.environ['HOME']}/git/cloak-compiler/test/demo_output/{file_name}"
    out, err = subprocess.Popen(
        f"solc --combined-json abi,bin,bin-runtime,hashes --evm-version homestead --optimize {file_path}",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
    cj = json.loads(out)
    j = cj["contracts"][f"{file_path}:CloakPKI"]
    abi = j["abi"]
    bi = j["bin"]

    ct = w3.eth.contract(address="0x8Ac2d5446F9583f993A51118F927a0Bdd9043bFd", abi=abi)
    fn = ct.functions.announcePk(get_pk_pem(owner.account.key.hex()))
    signed = acc.signTransaction(fn.buildTransaction({'nonce': 0, "gas": "0x461fb", "gasPrice": 0}))
    tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
    w3.eth.waitForTransactionReceipt(tx_hash)
    # res = ct.functions.getPk([owner.account.address]).call()
    # print(f"register_pki:{res}")

def test_mpt(ccf_client):
    compile_dir = os.environ["HOME"] + "/git/cloak-compiler/test/demo_output/"
    w3 = web3.Web3(provider.CCFProvider(ccf_client))
    owner_1 = Caller(web3.Account.from_key("0x55b99466a43e0ccb52a11a42a3b4e10bfba630e8427570035f6db7b5c22f689e"), w3)
    owner_2 = Caller(web3.Account.create(), w3)
    # register_pki(owner_1)
    register_pki(owner_2)
    print(f"owner_1:{owner_1.account.address}, owner_2:{owner_2.account.address}")
    file_path = compile_dir + "private_contract.sol"
    process = subprocess.Popen(
        f"solc --combined-json abi,bin,bin-runtime,hashes --evm-version homestead --optimize {file_path}",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = process.communicate()
    print(err)
    cj = json.loads(out)
    demo = cj["contracts"][f"{file_path}:Demo"]
    abi = demo["abi"]
    bi = demo["bin"]
    print(f"hashs:{demo['hashes']}")
    codeHash = web3.Web3.keccak(open(file_path, 'rb').read())
    spec = w3.eth.contract(abi=abi, bytecode=bi)
    deployed_receipt = owner_1.send_signed(spec.constructor(owner_2.account.address))
    print(f"deployed_addr:{deployed_receipt.contractAddress}")
    contractAddress = web3.Web3.toBytes(hexstr=deployed_receipt.contractAddress)

    policy = None
    with open(compile_dir + "policy.json", mode='rb') as f:
        policy = f.read()
    print(f"pt:{type(policy)}, ph:{web3.Web3.keccak(policy).hex()}")
    verifierAddr = web3.Web3.toBytes(hexstr="0x268f81287d34b583968adCE716bd28FaEcfb7459")
    sp = signPrivacy(owner_1.account.key, contractAddress, verifierAddr, codeHash, policy)
    res = owner_1.sendRawPrivacyPolicy(sp)
    print(f"res:{res}")

    # mpt
    ## transfer
    input_data = read_transfer_mpt_data(owner_2.account.address)
    print(input_data)
    mpt_params = signMpt(owner_1.account.key, contractAddress, input_data, 2)
    mpt_hash = owner_1.sendMultiPartyTransaction(mpt_params)
    print(f"transfer mpt hash:{mpt_hash}")
    time.sleep(5)

    ## deposit
    input_data = read_deposit_mpt_data()
    print(input_data)
    mpt_params = signMpt(owner_1.account.key, contractAddress, input_data, 2)
    mpt_hash = owner_1.sendMultiPartyTransaction(mpt_params)
    print(f"deposit mpt hash:{mpt_hash}")
    time.sleep(5)

    ## multi party transfer
    input_data_val, input_data_to = read_multiPartyTransfer_mpt_data(owner_2.account.address)
    print(input_data)
    mpt_params_1 = signMpt(owner_1.account.key, contractAddress, input_data_val, 2)
    mpt_hash = owner_1.sendMultiPartyTransaction(mpt_params_1)
    mpt_params_2 = signMpt(owner_2.account.key, web3.Web3.toBytes(hexstr=mpt_hash), input_data_to, 2)
    owner_2.sendMultiPartyTransaction(mpt_params_2)
    time.sleep(3)
    mpt_res = ccf_client.call("/app/cloak_get_mpt", {"tx_hash": mpt_hash}, "GET")
    print(f"multiPartyTransfer mpt hash:{mpt_hash}, mpt res:{mpt_res}")


if __name__ == "__main__":

    ccf_client = ccf.clients.CCFClient(
        config.host, 
        config.port, 
        config.ca, 
        config.cert, 
        config.key
        )
    # get_balance(ccf_client)
    # test_deploy(ccf_client)
    # cloak_prepare(ccf_client, "0x170BD87e16cf4460CE603308BfE8DA109d7754dF", "0x8Ac2d5446F9583f993A51118F927a0Bdd9043bFd")
    test_mpt(ccf_client)
    # test_get_sum(ccf_client)

