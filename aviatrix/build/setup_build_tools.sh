SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_DIR=${SCRIPT_DIR}/../../../trafficserver-buildtools

path_has_local_bin=`echo $PATH|grep -E "/\.local/bin"`
echo $path_has_local_bin
has_error=''
if [ ! -e ~/.local/bin ]; then
    echo Creating "\"\$HOME/.local/bin\""
    mkdir -p ~/.local/bin
    has_error=true
fi
if [ -z "$path_has_local_bin" ]; then
    export PATH=~/.local/bin/:$PATH
fi

export PKG_CONFIG_PATH=~/.local/lib/pkgconfig

#get the stuff
$SCRIPT_DIR/setup_build_tools_1.sh $BUILD_DIR
#build the stuff
$SCRIPT_DIR/setup_build_tools_2.sh $BUILD_DIR
