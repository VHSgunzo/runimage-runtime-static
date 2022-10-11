#!/bin/bash

export MAKEFLAGS="-j$(nproc)"

# BUILTIN_LIBS=1

platform="$(uname -s)"
platform_arch="$(uname -m)"

if [ -x "$(which apt 2>/dev/null)" ]
    then
        apt update && apt install -y \
            build-essential clang pkg-config git \
            libzstd-dev liblz4-dev liblzo2-dev liblzma-dev zlib1g-dev \
            libfuse-dev libsquashfuse-dev libsquashfs-dev
fi

if [ -d build ]
    then
        echo "= removing previous build directory"
        rm -rf build
fi

if [ -d release ]
    then
        echo "= removing previous release directory"
        rm -rf release
fi

# create release directory
mkdir release

if [[ ! -d src && ! -f "Makefile" ]]
    then
        # create build directory
        mkdir build
        pushd build
        # download runimage-runtime
        git clone https://github.com/VHSgunzo/runimage-runtime-static.git
        runimage_runtime_version="$(cd runimage-runtime-static && git describe --long --tags|\
                                    sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g')"
        mv runimage-runtime-static "runimage-runtime-${runimage_runtime_version}"
        echo "= downloading runimage-runtime v${runimage_runtime_version}"
        pushd runimage-runtime-${runimage_runtime_version}
    else
        runimage_runtime_version="$(git describe --long --tags|sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g')"
fi

echo "= building runimage-runtime"
[[ "$BUILTIN_LIBS" == 1 && "$platform_arch" == "x86_64" ]] && \
    CFLAGS=-Llibs-x86_64 make || \
    make

popd # runimage-runtime-${runimage_runtime_version}

popd # build

shopt -s extglob

echo "= extracting which binary"
[ -d build ] && \
    mv build/runimage-runtime-${runimage_runtime_version}/runtime-fuse2* release || \
    mv runtime-fuse2* release

echo "= create release tar.xz"
tar --xz -acf runimage-runtime-static-v${runimage_runtime_version}-${platform_arch}.tar.xz release
# cp runimage-runtime-static-*.tar.xz ~/ 2>/dev/null

if [ "$NO_CLEANUP" != 1 ]
    then
        echo "= cleanup"
        rm -rf release build
fi

echo "= runimage-runtime v${runimage-runtime_version} done"
