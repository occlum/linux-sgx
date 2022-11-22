#!/bin/bash
set -e

pushd `dirname $0` > /dev/null
SCRIPT_PATH=`pwd`
popd > /dev/null

# Uninstall old sdk
sudo /opt/intel/sgxsdk/uninstall.sh || true

# Compile SDK and install
make USE_OPT_LIBS=3 sdk_no_mitigation
make sdk_install_pkg_no_mitigation
sudo mkdir -p /opt/intel
cd /opt/intel
yes yes | sudo ${SCRIPT_PATH}/linux/installer/bin/sgx_linux_x64_sdk_*.bin
source /opt/intel/sgxsdk/environment

cd ${SCRIPT_PATH}
make -C psw/urts/linux
cd build/linux
ln -sf libsgx_enclave_common.so libsgx_enclave_common.so.1
export LD_LIBRARY_PATH=${SCRIPT_PATH}/build/linux/

cd ${SCRIPT_PATH}/external/sgx-emm/api_tests/
make clean
make
./test_mm_api

