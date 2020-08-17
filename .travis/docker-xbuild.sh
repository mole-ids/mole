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

if [ $TRAVIS_OS_NAME == "linux" ]; then
    cd ${TRAVIS_BUILD_DIR}

    docker build -t molebuilder -f docker/Dockerfile.build .

    version=$(git describe --abbrev=0)
    builddate=$(date +%FT%T%z)
    build=$(git rev-parse HEAD)

    docker run --rm -e "VERSION=${version}" -e "BUILDDATE=${builddate}" -e "BUILD=${build}" -v "${TRAVIS_BUILD_DIR}/build":/go/src/github.com/mole-ids/mole/build molebuilder linux
    docker run --rm -e "VERSION=${version}" -e "BUILDDATE=${builddate}" -e "BUILD=${build}" -v "${TRAVIS_BUILD_DIR}/build":/go/src/github.com/mole-ids/mole/build molebuilder windows
fi
