#!/bin/bash
git commit -a -m "$1"
git-dch -R
git commit -a -m "build"
export DEB_HOST_ARCH=i386
export ARCH=i386
export DIST=precise
git-buildpackage  --git-arch=$ARCH --git-dist=$DIST --git-tag -us -uc --git-pristine-tar
#git-buildpackage --git-pbuilder --git-arch=$ARCH --git-dist=$DIST --git-tag
