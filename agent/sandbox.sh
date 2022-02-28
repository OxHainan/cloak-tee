#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

VENV_DIR=${VENV_DIR:-.venv_ccf_sandbox}
PATH_HERE=$(dirname "$(realpath -s "$0")")

is_package_specified=false
is_js_bundle_specified=false

extra_args=("$@")

while [ "$1" != "" ]; do
    case $1 in
        -p|--package)
            is_package_specified=true
            shift
            ;;
        -p=*|--package=*)
            is_package_specified=true
            ;;
        --js-app-bundle)
            is_js_bundle_specified=true
            shift
            ;;
        --js-app-bundle=*)
            is_js_bundle_specified=true
            ;;
        *)
            ;;
    esac
    shift
done

echo "Setting up Python environment..."

if [ ! -f "${VENV_DIR}/bin/activate" ]; then
    python3.8 -m venv "${VENV_DIR}"
fi
# shellcheck source=/dev/null
source "${VENV_DIR}"/bin/activate
BINARY_DIR=.
CCF_DIR="${PATH_HERE}"/../CCF
SANDBOX_DIR=$CCF_DIR/tests/sandbox
START_NETWORK_SCRIPT="${PATH_HERE}"/../agent/start_network.py

if [ -f "${VENV_DIR}/bin/activate" ]; then
    pip install --disable-pip-version-check -q -U -e $CCF_DIR/python/
    pip install --disable-pip-version-check -q -U -r $BINARY_DIR/../agent/requirements.txt
    pip install --disable-pip-version-check -q -U -r $CCF_DIR/python/requirements.txt
    pip install --disable-pip-version-check -q -U -r $CCF_DIR/tests/requirements.txt
fi

echo "Python environment successfully setup"

export CURL_CLIENT=ON
exec python "${START_NETWORK_SCRIPT}" \
    --binary-dir "${BINARY_DIR}" \
    --enclave-type virtual \
    --initial-member-count 1 \
    --constitution $SANDBOX_DIR/actions.js \
    --constitution $SANDBOX_DIR/validate.js \
    --constitution $SANDBOX_DIR/resolve.js \
    --constitution $SANDBOX_DIR/apply.js \
    --ledger-chunk-bytes 5000000 \
    --snapshot-tx-interval 10000 \
    --label sandbox \
    "${extra_args[@]}"
