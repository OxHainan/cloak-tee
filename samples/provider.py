# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
import itertools
from eth_utils import types
import web3
import ccf.clients
from loguru import logger as LOG
import http
import json
class CCFProvider(web3.providers.BaseProvider):
    def __init__(self, ccf_client, logging=False):
        self.middlewares = []
        self.ccf_client = ccf_client
        if not logging:
            self.disable_logging()

        response = self.ccf_client.get("/app/api")
        self.supported_methods = response.body.json()["paths"]
        # print(json.dumps(self.supported_methods, sort_keys=True, indent=4, separators=(', ', ': '), ensure_ascii=False))

    def disable_logging(self):
        pass

    def make_request(self, method, params):
        http_path = "/" + method
        if http_path not in self.supported_methods:
            raise web3.exceptions.CannotHandleRequest(
                f"CCF does not support '{method}'"
            )

        http_verb = "POST" if "post" in self.supported_methods[http_path] else "GET"

        # if method == "cloak_sendPrivacyPolicy":
        #     params[0] = params[0].hex()
            
        response = self.ccf_client.call("/app"+http_path, params, http_verb)
     
        if response.status_code != http.HTTPStatus.OK:
            LOG.warning("CCF fail to process HTTP request: "+str(response))

        print("response: {}".format(response.body))
        return response.body.json()

    def isConnected(self):
        try:
            r = self.ccf_client.get("/node/state")
            return r.status_code == http.HTTPStatus.OK
        except ccf.clients.CCFConnectionException as con_exec:
            LOG.warning("Fail to connect CCF node: " + con_exec)

        return False
        

