#!/usr/bin/env bash

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

if ! [ "$BEFORE_DEPLOY_RUN" ]; then
    export BEFORE_DEPLOY_RUN=1

    cd "$TRAVIS_BUILD_DIR"
    git fetch --tags

    if [ ! -z $TRAVIS_TAG ]; then
        echo "#############################"
        echo "##     MOLE X-COMPILER     ##"
        echo "#############################"
        echo 
        if [ $TRAVIS_OS_NAME == "linux" ]; then
            bash .travis/docker-xbuild.sh
            sha256sum build/mole_{linux,windows}* >> build/mole_sha256_checksum.txt
        fi
        if [ $TRAVIS_OS_NAME == "osx" ]; then
            bash .travis/macosx-build.sh
            shasum -a 256 -b build/mole_darwin* >> build/mole_sha256_checksum.txt
        fi        
    fi

    if [ $TRAVIS_OS_NAME == "linux" ]; then
        echo "Download documentation generator"
        curl -sfL https://raw.githubusercontent.com/containous/structor/master/godownloader.sh | bash -s -- -b $GOPATH/bin ${STRUCTOR_VERSION}
        
        echo "Build documentation"
        "$GOPATH/bin/structor" -o mole-ids -r mole \
                --force-edit-url \
                --dockerfile-url="https://raw.githubusercontent.com/mole-ids/mole/master/docs/docs.Dockerfile" \
                --menu.js-url="https://raw.githubusercontent.com/mole-ids/mole/master/docs/structor-menu.js.gotmpl" \
                --exp-branch=master --debug
        chown -R $UID site
    fi
fi
