#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set -e

if [ ! -f "env/bin/activate" ]
    then
        python3.8 -m venv env
fi

source env/bin/activate

# pip install wheel
# pip install -U -r ../tests/requirements.txt


export EVM4CCF_HOME=/project/evm4ccf
export CONTRACTS_DIR=${EVM4CCF_HOME}/cmake/../tests/contracts

ctest "$@"