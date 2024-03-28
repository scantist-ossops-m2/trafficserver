SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_DIR=${SCRIPT_DIR}/../../../trafficserver-buildtools
if [ ! -z $1 ]; then
    BUILD_DIR=$1
fi
mkdir -p $BUILD_DIR
is_ubuntu18=`lsb_release -a|grep "Ubuntu 18.04"`
if [ ! -z "$is_ubuntu18" ]; then
    sudo apt install wget
    cd /tmp
    mkdir cmakedownload
    cd cmakedownload
    wget wget https://github.com/Kitware/CMake/releases/download/v3.25.3/cmake-3.25.3-linux-x86_64.tar.gz
    tar xvzf cmake-3.25.3-linux-x86_64.tar.gz
    cd cmake-3.25.3-linux-x86_64
    mkdir -p ~/.local/
    cp  -r * ~/.local/
    ls ~/.local/bin
    if [ ! -d make-4.3 ]; then
      cd $BUILD_DIR

      wget https://ftp.gnu.org/gnu/make/make-4.3.tar.gz
      tar xfz make-4.3.tar.gz
      cd make-4.3/
      ./configure --prefix=/home/develop/.local
      make install

    fi
fi
cd $BUILD_DIR
pwd
MY_INSTALL_DIR=$HOME/.local
sudo apt install -y build-essential autoconf libtool pkg-config cmake
if [ ! -d grpc ]; then
    echo 'grpc does not exist cloning'
    mkdir -p $HOME/.local
    git clone --recurse-submodules -b v1.48.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc
    cd grpc
    mkdir -p cmake/build
    pushd cmake/build
    cmake -DgRPC_INSTALL=ON \
      -DgRPC_BUILD_TESTS=OFF \
      -DCMAKE_INSTALL_PREFIX=$MY_INSTALL_DIR \
      ../..
    popd
fi
cd $BUILD_DIR
if [ ! -d libswoc ]; then
    echo 'libswoc does not exist, cloning'
    git clone https://github.com/SolidWallOfCode/libswoc
    cd libswoc
    # we should change this to a version
    echo checking out libswoc ${libswoc_version}
    git checkout ${libswoc_version}
    git status
    # don't build examples
    echo > example/CMakeLists.txt
    echo > unit_tests/CMakeLists.txt
    mkdir -p cmake/build 
    pushd cmake/build
    
    cmake -DCMAKE_INSTALL_PREFIX=$MY_INSTALL_DIR \
      ../..
    popd
fi

