#!/bin/bash
pushd `dirname $0` > /dev/null
SCRIPT_PATH=`pwd`
popd > /dev/null

# Uninstall and clean up
sudo /opt/intel/sgxsdk/uninstall.sh
sudo /opt/intel/sgxpsw/uninstall.sh
make clean

make preparation

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

# Compile PSW and install
# Note that the compilation of PSW requires the installation of SDK.
cd ${SCRIPT_PATH}
make psw
make psw_install_pkg
cd /opt/intel
sudo ${SCRIPT_PATH}/linux/installer/bin/sgx_linux_x64_psw_*.bin --no-start-aesm

# Compile and install DCAP package
# The DCAP package is not the latest. It contains an out-of-data TCB.
cd ${SCRIPT_PATH}

DEB_DISTRO_URL=https://download.01.org/intel-sgx/sgx-dcap/1.8/linux/distro/ubuntu18.04-server/debian_pkgs

if [ -f "/etc/debian_version" ]; then
    make deb_psw_pkg

    cd linux/installer/deb

    # Get Intel-signed application enclaves from the official website.
    mkdir libsgx-ae
    pushd libsgx-ae
    wget ${DEB_DISTRO_URL}/libs/libsgx-ae-qe3/libsgx-ae-qe3_1.8.100.2-bionic1_amd64.deb \
        ${DEB_DISTRO_URL}/libs/libsgx-ae-qve/libsgx-ae-qve_1.8.100.2-bionic1_amd64.deb \
        ${DEB_DISTRO_URL}/utils/libsgx-ae-pce/libsgx-ae-pce_2.11.100.2-bionic1_amd64.deb
    sudo dpkg -i libsgx-ae-pce_*.deb libsgx-ae-qe3_*.deb libsgx-ae-qve_*.deb
    popd

    sudo dpkg -i libsgx-enclave-common/libsgx-enclave-common_*.deb \
        libsgx-quote-ex/libsgx-quote-ex_*.deb \
        libsgx-urts/libsgx-urts_*.deb

    cd sgx-aesm-service/
    sudo dpkg -i libsgx-dcap-ql_*.deb libsgx-qe3-logic_*.deb libsgx-pce-logic_*.deb \
        libsgx-dcap-quote-verify_*.deb libsgx-dcap-ql_*.deb libsgx-dcap-ql-dev_*.deb \
        libsgx-dcap-default-qpl_*.deb libsgx-dcap-default-qpl-dev_*.deb \
        libsgx-dcap-quote-verify-dev_*.deb

elif command -v rpm >/dev/null 2>&1; then
    make rpm_psw_pkg

    cd linux/installer/rpm

    # Get Intel-signed application enclaves from the official website.
    # Libaries have dependencies on AE. Install AE first.
    mkdir libsgx-ae
    pushd libsgx-ae
    wget https://download.01.org/intel-sgx/sgx-dcap/1.8/linux/distro/centos8.1-server/sgx_rpm_local_repo.tgz
    tar -xvf sgx_rpm_local_repo.tgz
    cd sgx_rpm_local_repo
    sudo rpm -ivh libsgx-ae-pce*.rpm libsgx-ae-qe3*.rpm libsgx-ae-qve*.rpm
    popd

    sudo rpm -ivh libsgx-enclave-common/libsgx-enclave-common*.rpm \
        libsgx-quote-ex/libsgx-quote-ex*.rpm \
        libsgx-urts/libsgx-urts*.rpm

    cd sgx-aesm-service/
    sudo rpm -ivh libsgx-dcap-ql*.rpm libsgx-qe3-logic*.rpm libsgx-pce-logic*.rpm \
        libsgx-dcap-quote-verify*.rpm libsgx-dcap-ql*.rpm libsgx-dcap-ql-dev*.rpm \
        libsgx-dcap-default-qpl*.rpm libsgx-dcap-default-qpl-dev*.rpm \
        libsgx-dcap-quote-verify-dev*.rpm

else
    echo "unsupported package system"
fi
