import web3
from loguru import logger as LOG

class Web3Client:
    def __init__(
        self,
        hostname: str,
    ):
        self.hostname = hostname
        self.w3 = web3.Web3(web3.HTTPProvider(hostname))
    
    def send(self, args):
        try:
            self.w3.eth.send_raw_transaction(args)
            return True
        except Exception as e:
            LOG.warning(e.message)
            return False
    
    def call(self, args):
        try:
            res = self.w3.eth.call({
                "to": args["to"],
                "from": args["from"],
                "data": args["data"],
            })
            return res.hex()

        except Exception as e:
            LOG.warning(e.message)
    
    def account(self):
        try:
            res = self.w3.eth.get_accounts()
            return res[0]
        except Exception as e:
            LOG.warning(e.message)

    def isSyncing(self):
        return self.w3.eth.syncing == True