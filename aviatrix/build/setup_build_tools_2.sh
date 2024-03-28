SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_DIR=${SCRIPT_DIR}/../../../trafficserver-buildtools

if [ ! -z $1 ]; then
    BUILD_DIR=$1
else
    BUILD_DIR
fi
MY_INSTALL_DIR=$HOME/.local
cd $BUILD_DIR
pwd
cd grpc
pushd cmake/build
ncpus=$(grep -E '^processor'  /proc/cpuinfo | wc -l)
make -j$ncpus
make install
popd
pushd third_party/re2
CPPFLAGS=-fPIC make -j$ncpus -e prefix=$MY_INSTALL_DIR static static-install
popd
cd $BUILD_DIR/libswoc/cmake/build
c++ --version
echo $libswoc_version
make -j$ncpus  -e VERBOSE=true --trace -e prefix=$MY_INSTALL_DIR install