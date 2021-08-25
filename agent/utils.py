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
from ccf.clients import CCFClient, Identity


def get_ccf_client(args: argparse.Namespace) -> CCFClient:
    sandbox_common = args.build_path + "/workspace/sandbox_common/"
    ca = sandbox_common + "networkcert.pem"
    user0 = Identity(sandbox_common + "user0_privk.pem", sandbox_common + "user0_cert.pem", "")
    return CCFClient("127.0.0.1", args.cloak_tee_port, ca, user0)
