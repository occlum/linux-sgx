#!/bin/bash
pushd `dirname $0` > /dev/null
SCRIPT_PATH=`pwd`
popd > /dev/null

# Uninstall and clean up
sudo /opt/intel/sgxsdk/uninstall.sh
sudo /opt/intel/sgxpsw/uninstall.sh
make clean

# Compile SDK and install
make sdk
make sdk_install_pkg
sudo mkdir -p /opt/intel
cd /opt/intel
yes yes | sudo ${SCRIPT_PATH}/linux/installer/bin/sgx_linux_x64_sdk_*.bin

# Compile PSW and install
# Note that the compilation of PSW requires the installation of SDK.
cd ${SCRIPT_PATH}
make psw
make psw_install_pkg
cd /opt/intel
sudo ${SCRIPT_PATH}/linux/installer/bin/sgx_linux_x64_psw_*.bin --no-start-aesm
