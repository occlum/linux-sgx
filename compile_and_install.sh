#!/bin/bash
pushd `dirname $0` > /dev/null
SCRIPT_PATH=`pwd`
popd > /dev/null

# Uninstall old sdk
sudo /opt/intel/sgxsdk/uninstall.sh

# Compile SDK and install
if [ "no_mitigation" = "$1" ]; then
  make sdk_no_mitigation
  make sdk_install_pkg_no_mitigation
else
  make sdk
  make sdk_install_pkg
fi
sudo mkdir -p /opt/intel
cd /opt/intel
yes yes | sudo ${SCRIPT_PATH}/linux/installer/bin/sgx_linux_x64_sdk_*.bin

