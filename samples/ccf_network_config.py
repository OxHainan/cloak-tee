import os

# Node address or domain (str)
host = "127.0.0.1"

# Node port (int)   
port = 8000           

# Network certificate path
ca = os.path.join(os.getenv("EVM4CCF_HOME"), "build/workspace/sandbox_common/networkcert.pem")

# User client certificate path
cert = os.path.join(os.getenv("EVM4CCF_HOME"), "build/workspace/sandbox_common/user0_cert.pem")

# User client private key certificate path
key = os.path.join(os.getenv("EVM4CCF_HOME"), "build/workspace/sandbox_common/user0_privk.pem")
