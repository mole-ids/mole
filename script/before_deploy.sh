#!/usr/bin/env bash

if ! [ "$BEFORE_DEPLOY_RUN" ]; then
    export BEFORE_DEPLOY_RUN=1

    if [ x$TRAVIS_TAG != x"" ]; then
        echo "Building binaries"
        make build
        cd build
        ARCH=$(uname -m)
        sha256sum -b mole > "mole_linux_$ARCH.sha256"
        mv mole "mole_linux_$ARCH"
        cd -
    fi;

    echo "Download documentation generator"
    curl -sfL https://raw.githubusercontent.com/containous/structor/master/godownloader.sh | bash -s -- -b $GOPATH/bin ${STRUCTOR_VERSION}
    
    echo "Build documentation"
    "$GOPATH/bin/structor" -o mole-ids -r mole \
            --force-edit-url \
            --dockerfile-url="https://raw.githubusercontent.com/mole-ids/mole/master/docs/docs.Dockerfile" \
            --menu.js-url="https://raw.githubusercontent.com/mole-ids/mole/master/docs/theme/structor-menu.js.gotmpl" \
            --exp-branch=master --debugg
    chown -R $UID site
fi
