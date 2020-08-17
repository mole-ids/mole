#!/bin/ash

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

function linuxCommon() {
    export COMPILER=x86_64-alpine-linux-musl-gcc

    cd ${YARA_SRC_DIR} \
    && ./bootstrap.sh \
    && ./configure \
        CC=/usr/bin/${COMPILER} \
        --disable-shared \
        --prefix=${YARA_NIX_PREFIX} \
    && make \
    && make install

    cd ${LIBPCAP_SRC_DIR} \
    && ./configure \
        CC=/usr/bin/${COMPILER} \
        --disable-shared \
        --prefix=${LIBPCAP_PREFIX} \
    && make \
    && make install

    export GOOS=linux
    export GOARCH=amd64
    export CGO_ENABLED=1
    export CC=/usr/bin/${COMPILER}
}

function buildWindows() {
    export HOST=x86_64-w64-mingw32
    export COMPILER=${HOST}-gcc

    cd ${YARA_SRC_DIR} \
    && ./bootstrap.sh \
    && ./configure \
        CC=/usr/bin/${COMPILER} \
        --host=${HOST} \
        --disable-shared \
        --prefix=${YARA_WIN_PREFIX} \
    && make \
    && make install

    export GOOS=windows
    export GOARCH=amd64
    export CGO_ENABLED=1
    export CC=/usr/bin/${COMPILER}
    export PKG_CONFIG_PATH="${YARA_WIN_PREFIX}/lib/pkgconfig"
    export GO_LDFLAGS="-w -s -X 'github.com/mole-ids/mole/cmd.AppName=MoleIDS' -X 'github.com/mole-ids/mole/cmd.Version=${VERSION}' -X 'github.com/mole-ids/mole/cmd.BuildDate=${BUILDDATE}' -X 'github.com/mole-ids/mole/cmd.BuildHash=${BUILD}' -extldflags '-static'"

    cd ${MOLE_HOME}

    go build -race -ldflags="${GO_LDFLAGS}" -o build/mole_${GOOS}_${GOARCH}.exe main.go
}

function buildLinux() {
    linuxCommon

    export PKG_CONFIG_PATH="${YARA_NIX_PREFIX}/lib/pkgconfig:${LIBPCAP_PREFIX}/lib/pkgconfig" \
    export GO_LDFLAGS="-w -s -X 'github.com/mole-ids/mole/cmd.AppName=MoleIDS' -X 'github.com/mole-ids/mole/cmd.Version=${VERSION}' -X 'github.com/mole-ids/mole/cmd.BuildDate=${BUILDDATE}' -X 'github.com/mole-ids/mole/cmd.BuildHash=${BUILD}' -extldflags '-static'"

    cd ${MOLE_HOME}
    
    go build -race -ldflags="${GO_LDFLAGS}" -o build/mole_${GOOS}_${GOARCH} main.go
}

function buildLinuxPFring() {
    linuxCommon

    cd ${PF_RING_LIB_DIR} \
    && ./configure \
        CC=/usr/bin/${COMPILER} \
        --prefix=${PF_RING_LIB_PREFIX} \
    && make \
    && make install    
}

if [ "$#" -lt 1 ]; then
    echo "Need an option."
    echo "Options:"
    echo "  * linux"
    echo "  * linux pfring"
    echo "  * windows"
    exit 1
fi

echo "Building MoleIDS"
if [ -z ${VERSION} ]; then
    export VERSION=v0.0.0-dev
    echo "WARNING: Environment VERSION variable not defined. Using ${VERSION}"
else
    echo "Version: ${VERSION}"
fi

if [ -z ${BUILDDATE} ]; then
    export BUILDDATE=$(date +%FT%T%z)
    echo "WARNING: Environment BUILDDATE variable not defined. Using ${BUILDDATE}"
else
    echo "Build Date: ${BUILDDATE}"
fi

if [ -z ${BUILD} ]; then
    export BUILD=$(git rev-parse HEAD)
    echo "WARNING: Environment BUILD variable not defined. Using ${BUILD}"
else
    echo "Build ID: ${BUILD}"
fi

echo -n "OS/ARCH selected "

case "$1" in
    windows)
        echo "Windows/amd64"
        buildWindows
    ;;
    linux)
        echo -n "Linux/amd64"
        if [ x"$2" == x"pfring" ]; then
            echo "with PF_Ring"
            buildLinuxPFring
        else
            echo
            buildLinux
        fi
    ;;
esac

