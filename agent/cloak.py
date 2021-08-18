import ccf
import argparse
import subprocess
import agent
import time
import os
import signal
import select
import traceback
import utils
from multiprocessing import Process
from ccf.clients import CCFClient, Identity


def get_args():
    parser = argparse.ArgumentParser(description='cloak manager')
    sp = parser.add_subparsers(title="command", dest="command")

    setup = sp.add_parser("setup-cloak-service")
    setup.add_argument('--build-path', help='cloak-tee build path', required=True)
    setup.add_argument('--pki-address', help='deployed pki address', required=True)
    setup.add_argument('--cloak-service-address', help='deployed cloak service address', required=True)
    setup.add_argument('--cloak-tee-port', type=int, help='cloak tee port', default=8000)
    setup.add_argument('--blockchain-http-uri', help='blockchain http uri', default="http://127.0.0.1:8545")

    args = parser.parse_args()
    return args


class Cloak:
    def __init__(self, args):
        self.args = args

    def run(self):
        if (self.args.command == "setup-cloak-service"):
            try:
                cloak_tee_proc = self.run_cloak_tee()
                agent_proc = self.run_cloak_tee_agent()
                self.prepare_cloak_tee()
                cloak_tee_proc.wait()
                agent_proc.join()
            except Exception as e:
                traceback.print_exc()
                print(f"err:{e}")
                if cloak_tee_proc:
                    os.killpg(os.getpgid(cloak_tee_proc.pid), signal.SIGTERM)
                if agent_proc:
                    agent_proc.kill()

    def run_cloak_tee(self):
        print("start cloak-tee")
        process = subprocess.Popen(
                "/opt/ccf-0.15.2/bin/sandbox.sh -p libevm4ccf.virtual.so", 
                cwd=self.args.build_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        ccf_client.call("/app/cloak_prepare", {
            "pki_addr": self.args.pki_address,
            "cloak_service_addr": self.args.cloak_service_address
        })
        print("cloak-prepare DONE")


if __name__ == "__main__":
    args = get_args()
    print(args)
    cloak = Cloak(args)
    cloak.run()
