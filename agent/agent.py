import pyinotify
import argparse
import json
from loguru import logger as LOG
import traceback
import sys
import http

class Handler(object):
    def __init__(self, args):
        self.args = args

    def send(self, method, data):
        with self.args.cloak.client("user0") as c:
            r = c.post("/app/" + method, data)
            assert r.status_code == http.HTTPStatus.OK.value

    def call(self, method, data):
        with self.args.cloak.client() as c:
            r = c.get(method, data)
            assert r.status_code == http.HTTPStatus.OK.value

    def handle_request_old_state(self, msg):
        res = self.args.w3.call(msg)
        self.send("eth_sync_old_states", {"tx_hash": msg["tx_hash"], "data": res})
    
    def handle_request_public_keys(self, msg):
        res = self.args.w3.call(msg)
        self.send("eth_sync_public_keys", {"tx_hash": msg["tx_hash"], "data": res})
    
    def handle_sync_result(self, msg):
        if self.args.w3.send(msg["data"]):
            self.send("cloak_sync_report", {"id": msg["tx_hash"], "result": "SYNCED"})
        else:
            self.send("cloak_sync_report", {"id": msg["tx_hash"], "result": "FAILED"})

    def handle_register_tee_addr(self, msg):
        if self.args.w3.send(msg["message"]):
            LOG.info("Cloak Service Deploy Success")
        else:
            sys.exit(1)

    def handle_sync_propose(self, msg):
        if self.args.w3.send(msg["data"]):
            self.send("cloak_sync_propose", {"id": msg["tx_hash"], "success": True})
        else:
            self.send("cloak_sync_propose", {"id": msg["tx_hash"], "success": False})


    def handle_agent_log(self, info: str):
        info_json = json.loads(info)
        if info_json["tag"] == "request_old_state":
            self.handle_request_old_state(info_json["message"])
        elif info_json["tag"] == "request_public_keys":
            self.handle_request_public_keys(info_json["message"])
        elif info_json["tag"] == "sync_result":
            self.handle_sync_result(info_json["message"])
        elif info_json["tag"] == "register_tee_addr":
            self.handle_register_tee_addr(info_json)
        elif info_json["tag"] == "propose": 
            self.handle_sync_propose(info_json["message"])
        else:
            raise Exception(f"invalid tag: {info_json['tag']}")

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, cmd_args, *args, **kwargs):
        super(EventHandler, self).__init__(*args, **kwargs)
        self.args = cmd_args
        self.file = open(cmd_args.workspace + "/sandbox_0/out", "r")
        self.file.seek(0, 2)
        self.decode_lines()
    
    def process_IN_MODIFY(self, event):
        self.decode_lines()
    
    def decode_lines(self):
        while line:= self.file.readline():
            pos = line.find("ShouokOn")
            if pos == -1:
                continue
                
            new_line = line[pos +8:]
            pos = new_line.find("ShouokOn")
            if pos == -1:
                continue
            try:
                Handler(self.args).handle_agent_log(new_line[:pos])
            except Exception as e:
                traceback.print_exc()
        

def event_handler(args: argparse.Namespace):
    wm = pyinotify.WatchManager()
    handler = EventHandler(args)
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(args.workspace + "/sandbox_0/out", pyinotify.IN_MODIFY, rec=True)
    notifier.loop()
