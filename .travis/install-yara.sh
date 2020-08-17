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


## Colors
RED="\e[31m"
GREEN="\e[32m"
RESET="\e[0m"

YARA_PATH=$(mktemp -d -t yara-XXXXX)

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
        exit 1
    else
        echo -e "${GREEN} OK ${RESET}"
    fi
}

function compileYara() {
    echo -n "[*] Bootstraping, configuring, and compiling Yara..."
    cd ${YARA_PATH}

    ERROR=$(./bootstrap.sh 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Bootstrap error${RESET}"
        echo ${ERROR}
        exit 1
    else
        echo -ne "\n\t[+] Bootstrap: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(./configure --without-crypto --disable-shared --enable-static 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Configure error${RESET}"
        echo ${ERROR}
        exit 1
    else
        echo -ne "\n\t[+] Configure: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(make 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -ne "\n\t${RED}[-] Make error${RESET}"
        echo ${ERROR}
        exit 1
    else
        echo -ne "\n\t[+] Make: ${GREEN} OK ${RESET}"
    fi

    ERROR=$(make install 2>&1 >/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\n\t${RED}[-] Make install error${RESET}"
        echo ${ERROR}
        exit 1
    else
        echo -e "\n\t[+] Make install: ${GREEN} OK ${RESET}"
    fi

    echo "[*] Yara compiled successfully"
}

downloadYara 4.0.2
compileYara
