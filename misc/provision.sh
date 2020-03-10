#/bin/sh

KVERSION=`uname -r`
KSHORTVERSION=`uname -r | awk -F. '{printf "%d.%d.%d", $1, $2, $3}'`
KERNEL_BUILD_HOST=matsumotory
KERNEL_BUILD_USER=matsumotory
KERNEL_LOCAL_VER=0.0.1

# use ccache
HOSTCXX=g++
CC=gcc
THREAD=2

sudo apt-get update
sudo apt-get -y install build-essential rake bison git gperf automake m4 \
                autoconf libtool cmake pkg-config libcunit1-dev ragel \
                libpcre3-dev clang-format-6.0
sudo apt-get -y remove nano
sudo apt-get -y install linux-headers-$KVERSION
sudo apt-get -y install gawk chrpath socat libsdl1.2-dev xterm libncurses5-dev lzop flex libelf-dev kmod
sudo apt-get install linux-source-$KSHORTVERSION

sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-6.0 1000

if [ -d ./build ]; then
        rm -rf ./build
fi

mkdir ./build
cd ./build
tar xf /usr/src/linux-source-$KSHORTVERSION.tar.bz2
cd ./linux-source-$KSHORTVERSION
cp /boot/config-$KVERSION .config
make olddefconfig
KBUILD_BUILD_HOST=$KERNEL_BUILD_HOST KBUILD_BUILD_USER=$KERNEL_BUILD_USER USE_CCACHE=1 CCACHE_DIR=~/.ccache make -j$THREAD HOSTCXX="$HOSTCXX" CC="$CC"


