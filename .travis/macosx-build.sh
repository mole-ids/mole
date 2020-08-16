#!/bin/bash

# Copyright 2020 Jaume Martin

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# 	http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

APPNAME=MoleIDS
BINDIR=build
VERSION=$(git describe --abbrev=0)
BUILD=$(git rev-parse HEAD)
BUILDDATE=$(date +%FT%T%z)

## Devel variables
if [ -z $TRAVIS_BUILD_DIR ]; then
    TRAVIS_BUILD_DIR=$(pwd)
fi

MOLE_PATH=${TRAVIS_BUILD_DIR}
BASE_PATH=$(mktemp -d -t mole)
SRC=main.go

SRC_BASE_PATH=${BASE_PATH}/src
PREFIX=${BASE_PATH}/dist

## Dependencies
YARA_VER=4.0.2
LIBPCAP_VER=1.9.1

YARA_PATH=${SRC_BASE_PATH}/yara
YARA_64_PREFIX=${PREFIX}/yara64
mkdir -p "$YARA_64_PREFIX"

LIBPCAP_PATH=${SRC_BASE_PATH}/libpcap
LIBPCAP_64_PREFIX=${PREFIX}/libpcap64
mkdir -p "$LIBPCAP_64_PREFIX"

## Colors
RED="\e[31m"
GREEN="\e[32m"
RESET="\e[0m"

function cleanUp() {
    echo -n "[*] Cleaning up the build pipeline..."
    ERROR=$(rm -rf ${BASE_PATH} 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\n\t${RED}[-] Error cleaning up the pipeline${RESET}"
        echo ${ERROR}
        exit 1
    else
        echo -e "${GREEN} OK ${RESET}"
    fi
}

function installDeps() {
    echo -n "[*] Installing dependencies..."
    
    DEPS="autoconf automake libtool make pkg-config git"
    ERROR=$(brew install ${DEPS} 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\n\t${RED}[-] Installing dependencies failed.${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -e "${GREEN} OK ${RESET}"
    fi
}

function downloadYara() {
    if [ $# -eq 1 ]; then
        YARA_VER="$1"
    fi

    YARA_GIT=https://github.com/VirusTotal/yara.git

    echo -n "[*] Cloning Yara v${YARA_VER} into ${YARA_PATH}..."
    if [ -d "${YARA_PATH}" ]; then
        echo -e "${GREEN} OK ${RESET} (directory exists)"
    else
        ERROR=$(git clone ${YARA_GIT} ${YARA_PATH} 2>&1 >/dev/null)
        if [ $? -ne 0 ]; then
            echo -e "\n\t${RED}[-] Cloning Yara failed.${RESET}"
            echo ${ERROR}
            cleanUp
            exit 1
        else
            echo -e "${GREEN} OK ${RESET}"
        fi
    fi

    echo -n "[*] Checking out Yara version v$YARA_VER..."
    cd ${YARA_PATH}

    ERROR=$(git checkout v${YARA_VER} 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\n\t${RED}[-] Repository checked out to v${YARA_VER} failed${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -e "${GREEN} OK ${RESET}"
    fi
}

function downloadLibpcap() {
    if [ $# -eq 1 ]; then
        LIBPCAP_VER="$1"
    fi
    LIBPCAP_GIT=https://github.com/the-tcpdump-group/libpcap.git

    echo -n "[*] Cloning Libpcap v${LIBPCAP_VER} into ${LIBPCAP_PATH}..."
    if [ -d "${LIBPCAP_PATH}" ]; then
        echo -e "${GREEN} OK ${RESET} (directory exists)"
    else
        ERROR=$(git clone ${LIBPCAP_GIT} ${LIBPCAP_PATH} 2>&1 >/dev/null)
        if [ $? -ne 0 ]; then
            echo -e "\n\t${RED}[-] Cloning libpcap failed.${RESET}"
            echo ${ERROR}
            cleanUp
            exit 1
        else
            echo -e "${GREEN} OK ${RESET}"
        fi
    fi

    echo -n "[*] Checking out libpcap version v$LIBPCAP_VER..."
    cd ${LIBPCAP_PATH}

    ERROR=$(git checkout libpcap-${LIBPCAP_VER} 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\n\t${RED}[-] Repository checked out to v${LIBPCAP_VER} failed${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -e "${GREEN} OK ${RESET}"
    fi
}

function compileYara() {
    os="darwin"
    arch="amd64"
    prefix="$1"

    echo -n "[*] Bootstraping, configuring, and compiling Yara for ${os}/${arch}..."
    cd ${YARA_PATH}

    ERROR=$(./bootstrap.sh 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Bootstrap error${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -ne "\n\t[+] Bootstrap: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(./configure --without-crypto --disable-shared --enable-static --prefix="${prefix}" 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Configure error${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -ne "\n\t[+] Configure: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(make 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Make error${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -ne "\n\t[+] Make: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(make install 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\n\t${RED}[-] Make install error${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -e "\n\t[+] Make install: ${GREEN} OK ${RESET}"
    fi

    echo "[*] Yara ${os}/${arch} compiled successfully"
}

function compileLibpcap() {
    os="darwin"
    arch="amd64"
    prefix="$1"

    echo -n "[*] Configuring and compiling Libpcap for ${os}/${arch}..."
    cd ${LIBPCAP_PATH}

    ERROR=$(./configure --disable-shared --prefix=${prefix} 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Configure error${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -ne "\n\t[+] Configure: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(make 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Make error${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -ne "\n\t[+] Make: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(make install 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\n\t${RED}[-] Make install error${RESET}"
        echo ${ERROR}
        cleanUp
        exit 1
    else
        echo -e "\n\t[+] Make install: ${GREEN} OK ${RESET}"
    fi

    echo "[*] Libpcap ${os}/${arch} compiled successfully"
}

installDeps

downloadYara "$YARA_VER"
downloadLibpcap "$LIBPCAP_VER"

compileYara "$YARA_64_PREFIX"
compileLibpcap "$LIBPCAP_64_PREFIX"

cd ${MOLE_PATH}

GOOS=darwin
GOARCH=amd64
GO_LDFLAGS="-w -s -X 'github.com/mole-ids/mole/cmd.AppName=${APPNAME}' -X 'github.com/mole-ids/mole/cmd.Version=${VERSION}' -X 'github.com/mole-ids/mole/cmd.BuildDate=${BUILDDATE}' -X 'github.com/mole-ids/mole/cmd.BuildHash=${BUILD}' -extldflags '-static'"

echo -n "[*] Compiling Mole IDS for Darwin amd64..."
ERROR=$(CGO_ENABLED=1 \
        PKG_CONFIG_PATH="${YARA_64_PREFIX}/lib/pkgconfig:${LIBPCAP_64_PREFIX}/lib/pkgconfig" \
        go build -x -race -ldflags="${GO_LDFLAGS}" -o build/mole_${GOOS}_${GOARCH} main.go 2>&1 >/dev/null)
if [ $? -ne 0 ]; then
    echo -e "\n\t${RED}[-] MoleIDS compile error.${RESET}"
    echo ${ERROR}
    cleanUp
    exit 1
else
    echo -e "\n\t[+] MoleIDS compilation: ${GREEN} OK ${RESET}"
fi
