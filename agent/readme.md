# cloak service manager
## setup
cloak.py require python 3.8 or greater version, install dependencies:
```
pip install -r requirements.txt
```

to setup cloak-tee-agent, you need run cloak-tee first, and run:
```
python cloak.py setup-cloak-service --build-path <CLOAK-TEE BUILD PATH> --cloak-service-address <CLOAK SERVICE ADDRESS> --blockchain-http-uri <BLOCKCHAIN-HTTP-URI>
```

