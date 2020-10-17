# GCC support can be specified at major, minor, or micro version
# (e.g. 8, 8.2 or 8.2.0).
# See https://hub.docker.com/r/library/gcc/ for all supported GCC
# tags from Docker Hub.
# See https://docs.docker.com/samples/library/gcc/ for more on how to use this image
FROM ccfciteam/ccf-ci-18.04-oe-0.7.0-sgx:latest

LABEL Name=evm4ccf Version=1.0
