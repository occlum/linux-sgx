#!/usr/bin/env bash
#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


set -e

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="${SCRIPT_DIR}/../../../../"
BUILD_DIR="${ROOT_DIR}/build/linux"
LINUX_INSTALLER_DIR="${ROOT_DIR}/linux/installer"
LINUX_INSTALLER_COMMON_DIR="${LINUX_INSTALLER_DIR}/common"

INSTALL_PATH=${SCRIPT_DIR}/output

# Cleanup
rm -fr ${INSTALL_PATH}

# Get the architecture of the build from generated binary
get_arch()
{
    local a=$(readelf -h $BUILD_DIR/sgx_sign | sed -n '2p' | awk '{print $6}')
    test $a = 01 && echo 'x86' || echo 'x64'
}

ARCH=$(get_arch)

# Get the configuration for this package
source ${SCRIPT_DIR}/installConfig.${ARCH}

generate_pkgconfig_files() {
    local TEMPLATE_FOLDER=${SCRIPT_DIR}/pkgconfig/template
    local TARGET_FOLDER=${SCRIPT_DIR}/pkgconfig/${ARCH}
    local VERSION="$1"

    # Create pkgconfig folder for this architecture
    rm -fr ${TARGET_FOLDER}
    mkdir -p ${TARGET_FOLDER}

    # Copy the template files into the folder
    for pkgconfig_file in $(ls -1 ${TEMPLATE_FOLDER}); do
        sed -e "s:@LIB_FOLDER_NAME@:$LIB_DIR:" \
            -e "s:@SGX_VERSION@:$VERSION:" \
            ${TEMPLATE_FOLDER}/$pkgconfig_file > ${TARGET_FOLDER}/$pkgconfig_file
    done
}

# Get Intel(R) SGX version
SGX_VERSION=$(awk '/STRFILEVER/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')

# Generate pkgconfig files
generate_pkgconfig_files $SGX_VERSION

# Fetch the gen_source script
cp ${LINUX_INSTALLER_COMMON_DIR}/gen_source/gen_source.py ${SCRIPT_DIR}

# Copy the files according to the BOM
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/sdk_base.txt
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/sdk_${ARCH}.txt --cleanup=false
if [ "$1" = "cve-2020-0551" ]; then 
    python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/sdk_cve_2020_0551_load.txt --cleanup=false
    python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/sdk_cve_2020_0551_cf.txt --cleanup=false
fi
python ${SCRIPT_DIR}/gen_source.py --bom=../licenses/BOM_license.txt --cleanup=false

# Create the tarball
pushd ${INSTALL_PATH} &> /dev/null
tar -zcvf ${TARBALL_NAME} *
popd &> /dev/null
