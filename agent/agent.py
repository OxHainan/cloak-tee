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

import web3
import json
import sys
import pyinotify
import traceback
import utils
import time
import argparse
from ccf.clients import CCFClient


class Handler(object):
    def __init__(self, args):
        self.ccf_client = utils.get_ccf_client(args)
        self.w3 = web3.Web3(web3.HTTPProvider(args.blockchain_http_uri))

    def handle_request_old_state(self, msg):
        res = self.w3.eth.call({"to": msg["to"], "from": msg["from"], "data": msg["data"]})
        self.ccf_client.call("/app/eth_sync_old_states", {"tx_hash": msg["tx_hash"], "data": res.hex()})

    def handle_request_public_keys(self, msg):
        res = self.w3.eth.call({"to": msg["to"], "from": msg["from"], "data": msg["data"]})
        self.ccf_client.call("/app/eth_sync_public_keys", {"tx_hash": msg["tx_hash"], "data": res.hex()})

    def handle_sync_result(self, msg):
        try:
            utils.write2file({
                "name": "complete_propose",
                "id": msg["tx_hash"],
                "timestamp": int(round(time.time() * 1000))
            })

            tx_hash = self.w3.eth.send_raw_transaction(msg["data"])
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            utils.write2file({
                "name": "commit_complete",
                "id": msg["tx_hash"],
                "gasUsed": receipt['gasUsed']
            })
            self.ccf_client.call("/app/cloak_sync_report", {"id": msg["tx_hash"], "result": "SYNCED"})
        except Exception as err:
            self.ccf_client.call("/app/cloak_sync_report", {"id": msg["tx_hash"], "result": "FAILED"})
            raise
    
    def handle_sync_propose(self, msg):
        try:
            utils.write2file({
                "name": "later_propose",
                "id": msg["tx_hash"],
                "timestamp": int(round(time.time() * 1000))
            })

            tx_hash = self.w3.eth.send_raw_transaction(msg["data"])
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            utils.write2file({
                "name": "commit_propose",
                "id": msg["tx_hash"],
                "gasUsed": receipt['gasUsed']
            })

            self.ccf_client.call("/app/cloak_sync_propose", {"id": msg["tx_hash"], "success": True})
            utils.write2file({
                "name": "comfire_propose",
                "id": msg["tx_hash"],
                "timestamp": int(round(time.time() * 1000))
            })

        except Exception as err:
            self.ccf_client.call("/app/cloak_sync_propose", {"id": msg["tx_hash"], "success": False})
            raise

    def handle_register_tee_addr(self, msg):
        tx_hash = self.w3.eth.send_raw_transaction(msg)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        utils.write2file({
            "name": "deployCloakService",
            "contractAddress" : receipt['contractAddress'],
            "gasUsed": receipt['gasUsed']
        })

    def handle_agent_log(self, info: str):
        info_json = json.loads(info)
        if info_json["tag"] == "request_old_state":
            self.handle_request_old_state(info_json["message"])
        elif info_json["tag"] == "request_public_keys":
            self.handle_request_public_keys(info_json["message"])
        elif info_json["tag"] == "sync_result":
            self.handle_sync_result(info_json["message"])
        elif info_json["tag"] == "register_tee_addr":
            self.handle_register_tee_addr(info_json["message"])
        elif info_json["tag"] == "propose": 
            self.handle_sync_propose(info_json["message"])
        else:
            raise Exception(f"invalid tag: {info_json['tag']}");
        print(f"{info_json['tag']} succeeded")

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, cmd_args, *args, **kwargs):
        super(EventHandler, self).__init__(*args, **kwargs)
        self.args = cmd_args
        self.file = open(cmd_args.build_path + "/workspace/sandbox_0/out", "r")
        self.file.seek(0, 2)
        self.decode_lines()

    def process_IN_MODIFY(self, event):
        print('event received')
        self.decode_lines()

    def decode_lines(self):
        while line:= self.file.readline():
            pos = line.find("ShouokOn")
            if pos == -1:
                continue
            new_line = line[pos+8:]
            pos = new_line.find("ShouokOn")
            if pos == -1:
                continue
            try:
                Handler(self.args).handle_agent_log(new_line[:pos])
            except Exception as err:
                traceback.print_exc()
                print(f"ERROR: {err}")
        print("read end")

def loop_for_log(args: argparse.Namespace):
    wm = pyinotify.WatchManager()
    handler = EventHandler(args)
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(args.build_path + "/workspace/sandbox_0/out", pyinotify.IN_MODIFY, rec=True)
    notifier.loop()

