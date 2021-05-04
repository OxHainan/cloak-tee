import json
import os
import web3
import ccf
from utils import *
import provider
import ccf_network_config as config

from loguru import logger as LOG


class ERC20Contract:
    def __init__(self, contract):
        self.contract = contract

    def get_total_supply(self, caller):
        return caller.call(self.contract.functions.totalSupply())

    def get_token_balance(self, caller, address=None):
        if address is None:
            address = caller.account.address
        return caller.call(self.contract.functions.balanceOf(address))

    def print_balances(self, callers):
        balances = [
            (caller.account.address, self.get_token_balance(caller))
            for caller in callers
        ]
        for a, b in balances:
            LOG.info(f"{a}: {b}")

    def transfer_tokens(self, sender, to, amount):
        return sender.send_signed(
            self.contract.functions.transfer(to.account.address, amount)
        )

    def transfer_and_check(self, sender, to, amount):
        transfer_receipt = self.transfer_tokens(sender, to, amount)

        events = self.contract.events.Transfer().processReceipt(transfer_receipt)
        for e in events:
            args = e.args
            topic_src = args._from
            topic_dst = args._to
            topic_amt = args._value
            if (
                sender.account.address == topic_src
                and to.account.address == topic_dst
                and amount == topic_amt
            ):
                return True

        return False


def read_erc20_contract_from_file():
    env_name = "CONTRACTS_DIR"
    contracts_dir = os.getenv(env_name)
    if contracts_dir is None:
        raise RuntimeError(f"Cannot find contracts, please set env var '{env_name}'")
    file_path = os.path.join(contracts_dir, "ERC20_combined.json")
    return read_contract_from_file(file_path, "ERC20.sol:ERC20Token")


def test_deploy(ccf_client):
    erc20_abi, erc20_bin = read_erc20_contract_from_file()

    w3 = web3.Web3(provider.CCFProvider(ccf_client))

    owner = Caller(web3.Account.create(), w3)

    LOG.info("Contract deployment")
    erc20_spec = w3.eth.contract(abi=erc20_abi, bytecode=erc20_bin)
    deploy_receipt = owner.send_signed(erc20_spec.constructor(100000))

    ccf_client.erc20_contract_address = deploy_receipt.contractAddress
    ccf_client.owner_account = owner.account

    return ccf_client


def test_transfers(ccf_client):
    erc20_abi, erc20_bin = read_erc20_contract_from_file()

    LOG.info(f"ccf_client: {ccf_client.name}")
    w3 = web3.Web3(provider.CCFProvider(ccf_client))

    erc20_contract = ERC20Contract(
        w3.eth.contract(abi=erc20_abi, address=ccf_client.erc20_contract_address)
    )

    owner = Caller(ccf_client.owner_account, w3)
    alice = Caller(web3.Account.create(), w3)
    bob = Caller(web3.Account.create(), w3)

    LOG.info("Get balance of owner")
    owner_balance = erc20_contract.get_token_balance(owner)
    LOG.info(f"Owner balance: {owner_balance}")

    first_amount = owner_balance // 5
    LOG.info(
        "Transferring {} tokens from {} to {}".format(
            first_amount, owner.account.address, alice.account.address
        ),
        True,
    )
    assert erc20_contract.transfer_and_check(owner, alice, first_amount)

    second_amount = owner_balance - first_amount
    LOG.info(
        "Transferring {} tokens from {} to {}".format(
            second_amount, owner.account.address, bob.account.address
        )
    )
    assert erc20_contract.transfer_and_check(owner, bob, second_amount)

    third_amount = second_amount // 3
    LOG.info(
        "Transferring {} tokens from {} to {}".format(
            third_amount, bob.account.address, alice.account.address
        )
    )
    assert erc20_contract.transfer_and_check(bob, alice, third_amount,)

    LOG.info("Balances:")
    erc20_contract.print_balances([owner, alice, bob])

    # Send many transfers, pausing between batches so that notifications should be received
    for batch in range(3):
        for i in range(20):
            sender, receiver = random.sample([alice, bob], 2)
            amount = random.randint(1, 10)
            erc20_contract.transfer_and_check(
                sender, receiver, amount,
            )
        time.sleep(2)

    LOG.info("Final balances:")
    erc20_contract.print_balances([owner, alice, bob])

    return ccf_client

def test(ccf_client):
    erc20_abi, erc20_bin = read_erc20_contract_from_file()

    LOG.info(f"ccf_client: {ccf_client.name}")
    w3 = web3.Web3(provider.CCFProvider(ccf_client))
    owner = Caller(ccf_client.owner_account, w3)
    alice = Caller(web3.Account.create(), w3)
    bob = Caller(web3.Account.create(), w3)
    erc20_contract = ERC20Contract(
        w3.eth.contract(abi=erc20_abi, address=ccf_client.erc20_contract_address)
    )
    
    txHash = erc20_contract.transfer_tokens(owner, alice, 50)
    total = erc20_contract.get_token_balance(alice)
    receipt = w3.eth.getTransactionReceipt(txHash.transactionHash)
    print(total)
    print(receipt)
    # print(json.dumps(txHash, sort_keys=True, indent=4, separators=(', ', ': '), ensure_ascii=False))

if __name__ == "__main__":
    ccf_client = ccf.clients.CCFClient(
        config.host, 
        config.port, 
        config.ca, 
        config.cert, 
        config.key
    )

    test_deploy(ccf_client)
    # test_transfers(ccf_client)
    # test(ccf_client)
