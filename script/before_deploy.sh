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

    if [ x$TRAVIS_TAG != x"" ]; then
        echo "Building binaries"
        make build
        cd build
        sha256sum -b "mole_$GOOS_$GOARCH" > "mole_$GOOS_$GOARCH.sha256"
        cd -
    fi;

    echo "Download documentation generator"
    curl -sfL https://raw.githubusercontent.com/containous/structor/master/godownloader.sh | bash -s -- -b $GOPATH/bin ${STRUCTOR_VERSION}
    
    echo "Build documentation"
    "$GOPATH/bin/structor" -o mole-ids -r mole \
            --force-edit-url \
            --dockerfile-url="https://raw.githubusercontent.com/mole-ids/mole/master/docs/docs.Dockerfile" \
            --menu.js-url="https://raw.githubusercontent.com/mole-ids/mole/master/docs/structor-menu.js.gotmpl" \
            --debug
    chown -R $UID site
fi
