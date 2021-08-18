import argparse
from ccf.clients import CCFClient, Identity


def get_ccf_client(args: argparse.Namespace) -> CCFClient:
    sandbox_common = args.build_path + "/workspace/sandbox_common/"
    ca = sandbox_common + "networkcert.pem"
    user0 = Identity(sandbox_common + "user0_privk.pem", sandbox_common + "user0_cert.pem", "")
    return CCFClient("127.0.0.1", args.cloak_tee_port, ca, user0)

