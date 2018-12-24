#!/bin/bash
pushd `dirname $0` > /dev/null
SCRIPT_PATH=`pwd`
popd > /dev/null

sudo /opt/intel/sgxpsw/uninstall.sh
sudo /opt/intel/sgxsdk/uninstall.sh
sudo mkdir -p /opt/intel
cd /opt/intel
sudo ${SCRIPT_PATH}/linux/installer/bin/sgx_linux_x64_psw_*.bin
yes yes | sudo ${SCRIPT_PATH}/linux/installer/bin/sgx_linux_x64_sdk_*.bin
