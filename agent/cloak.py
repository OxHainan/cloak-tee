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

import ccf
import argparse
import subprocess
import agent
import time
import os
import json
import signal
import select
import traceback
import utils
import web3
from multiprocessing import Process
import sys
sys.path.append("../CCF/tests")
from infra.clients import CCFClient, Identity

def get_args():
    parser = argparse.ArgumentParser(description='cloak manager')
    sp = parser.add_subparsers(title="command", dest="command")

    setup_service = sp.add_parser("setup")
    setup_service.add_argument('--build-path', help='cloak-tee build path', required=True)
    setup_service.add_argument('--cloak-tee-port', type=int, help='cloak tee port', default=8000)
    setup_service.add_argument('--blockchain-http-uri', help='blockchain http uri', default="http://127.0.0.1:8545")
    setup_service.add_argument('--cloak-service-address', help='deployed cloak service address', default=None)
    setup_service.add_argument('--cloak-service-path', help='cloak service path', default=None)
    setup_service.add_argument('--manager-address', help='manager cloak service address', default=None)

    args = parser.parse_args()
    return args


class Cloak:
    def __init__(self, args):
        self.args = args
        self.cloak_service_addr = getattr(args, 'cloak_service_address', None)

    def run(self):
        if (self.args.command == "setup"):
            # self.deploy_sol_contracts()
            self.setup_cloak_service()

    def setup_cloak_service(self):
        try:
            cloak_tee_proc = self.run_cloak_tee()
            agent_proc = self.run_cloak_tee_agent()
            self.prepare_cloak_tee()
            cloak_tee_proc.wait()
            agent_proc.join()
        except Exception as e:
            traceback.print_exc()
            if cloak_tee_proc:
                os.killpg(os.getpgid(cloak_tee_proc.pid), signal.SIGTERM)
            if agent_proc:
                agent_proc.kill()

    def run_cloak_tee(self):
        print("start cloak-tee")
        process = subprocess.Popen(
                "./sandbox.sh -p libcloak.virtual.so".split(),
                cwd=self.args.build_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        s = select.poll()
        s.register(process.stdout)
        while True:
            time.sleep(0.1)
            line = process.stdout.readline().decode()
            print(line[:-1])
            if line.find("Press Ctrl+C to shutdown the network") != -1:
                print("cloak-tee started")
                break
        return process

    def run_cloak_tee_agent(self):
        p = Process(target=agent.loop_for_log, args=(self.args,))
        p.start()
        time.sleep(1)
        print("cloak-tee-agent started")
        return p

    def prepare_cloak_tee(self):
        ccf_client = utils.get_ccf_client(self.args)
        w3 = web3.Web3(web3.HTTPProvider(args.blockchain_http_uri))
        if self.args.manager_address is None:
            self.args.manager_address = w3.eth.get_accounts()[0]
            
        f = open(self.args.cloak_service_path + '/CloakService.json', 'r')
        contract = json.loads(f.read())
        f.close()
        ccf_client.call("/app/cloak_prepare", {
            "manager": self.args.manager_address,
            "cloakServiceContract": contract['bytecode']
        })
        
        print("cloak-prepare DONE")


if __name__ == "__main__":
    args = get_args()
    print(args)
    cloak = Cloak(args)
    cloak.run()
