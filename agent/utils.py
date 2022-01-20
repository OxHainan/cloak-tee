# Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import web3
import subprocess
import json
from ccf.clients import CCFClient, Identity


def get_ccf_client(args: argparse.Namespace) -> CCFClient:
    sandbox_common = args.build_path + "/workspace/sandbox_common/"
    ca = sandbox_common + "networkcert.pem"
    user0 = Identity(sandbox_common + "user0_privk.pem", sandbox_common + "user0_cert.pem", "")
    return CCFClient("127.0.0.1", args.cloak_tee_port, ca, user0)


def get_abi_and_bin(file_path: str, name: str):
    cmd = f"solc --combined-json abi,bin,bin-runtime,hashes --evm-version homestead --optimize {file_path}"
    out, err = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    if err:
        print(f"get_abi_and_bin failed:{err}")
        raise Exception(f"get_abi_and_bin failed:{err}")
    cj = json.loads(out)
    j = cj["contracts"][f"{file_path}:{name}"]
    return j["abi"], j["bin"]


def deploy_contract(file_path: str, name: str, w3: web3.Web3, acc: web3.eth.Account, nonce=0):
    abi, bi = get_abi_and_bin(file_path, name)
    contract = w3.eth.contract(abi=abi, bytecode=bi)
    tx = contract.constructor().buildTransaction({'nonce': nonce, "gasPrice": 0})
    signed = acc.signTransaction(tx)
    tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
    return w3.eth.waitForTransactionReceipt(tx_hash).contractAddress

def write2file(data: dict):
    file = open('data.txt', 'a')
    file.write(json.dumps(data) + "\n")
    file.close()