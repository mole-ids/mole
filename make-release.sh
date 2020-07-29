#!/bin/bash

function validate {
    if [ x$1 != x"y" ] && [ x$1 != x"Y" ]; then
        echo "See you later!"
        exit 0
    fi
}

echo "====================================="
echo "==       MOLE RELEASE MAKER        =="
echo "====================================="
echo 

if ! [ -x "$(command -v git)" ]; then
  echo 'Error: git is not installed.' >&2
  exit 1
fi

BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
LATEST_TAG=$(git describe --abbrev=0)
LATEST_COMMIT=$(git rev-parse $BRANCH_NAME | cut -c 1-8)
LATEST_COMMIT_MSG=$(git log -1 --pretty='%s')

echo "Your actual branch is:     $BRANCH_NAME"
echo "Your latest commit is:     $LATEST_COMMIT"
echo "Your latest commit msg is: $LATEST_COMMIT_MSG"
echo "Your latest tag is:        $LATEST_TAG"
echo

read -p "Do you want to continue [y/N]: " ok
validate $ok

read -p "New version to bump: " VERSION
read -p "You are about to bump the new version $VERSION, is it correct? [y/N]: " ok
validate $ok

read -p "Can you give a tag message? [Mole IDS $VERSION]: " TAG_MSG
if [ -z $TAG_MSG ]; then 
    TAG_MSG="Mole IDS $VERSION"
fi

case uname -s
    Darwin)
        sed -i "" -E "s/STRUCTOR_LATEST_TAG=.*$/STRUCTOR_LATEST_TAG=$VERSION/g" .travis.yml
    ;;
    Linux)
        sed -i -E "s/STRUCTOR_LATEST_TAG=.*$/STRUCTOR_LATEST_TAG=$VERSION/g" .travis.yml
    ;;
esac

git add --all
git commit -m "Bump $VERSION"
git tag -a $VERSION -m "$TAG_MSG"

echo "Job done!"
echo
echo "Release $VERSION is ready to be pushed"
echo "hint: git push origin $BRANCH_NAME --tags"
echo
echo "See you later!"
