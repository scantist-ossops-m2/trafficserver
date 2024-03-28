set -xeuo 

export OPENSSL=/opt/ssl/openssl_1.1.1
export DEB=ats_9.1.3


arg3=${3:-}
arg4=${4:-}
arg5=${5:-}

if [ -z $1 ]; then 
	echo script needs environment
	exit
fi
environment=$1
if [ -z $2 ]; then
	exit
fi
command=`echo $2 | grep -E '^build|plugins|clean$'`


if [ -z "$command" ]; then
	echo use clean, build, plugins
	exit
fi



SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source $SCRIPT_DIR/setup_$environment.sh

if [ "$command" == "plugins" ] && [ ! -e "$ats_install_path/bin" ]; then 
	command="build" 
fi

if [ $2 == "build" ]; then
	command=build
	if [ ! -e "/app/build/$environment/thirdparty-trafficserver" ]; then
		command=clean
	fi
fi



if [ $2 == "clean" ]; then
	command=$2
fi
echo Command: $command


if [ "$ats_install_path" == "" ]; then
	echo bailing, no ats install path
fi

echo $ats_install_path

mkdir -p /app/build/$environment/thirdparty-trafficserver
cd /app/build/$environment/thirdparty-trafficserver
if [ -e "/app/build/$environment/cloudn" ]; then
	unlink "/app/build/$environment/cloudn"
fi
ln -s /app_data/cloudn /app/build/$environment/cloudn 2>/dev/null 
if [ "$command" == "clean" ]; then
	echo cleaning up
	rm -rf *
fi

echo syncing
tar xf /app/source/copy-for-docker.tgz


if [ $2 == 'shell' ]; then
	exit
fi

cd /app/build/$environment/thirdparty-trafficserver/plugins/experimental/policy_driver
make -f Makefile-proto
cd /app/build/$environment/thirdparty-trafficserver

if [  $command == "shell" ]; then
	cd "/app/build/$1/thirdparty-trafficserver/plugins/"
	bash
	exit
fi

if [ $command == "clean" ]; then
	
	autoreconf -if
	./configure $(echo $configure_with)
	
fi


PKG_CONFIG_PATH=/root/.local/lib/pkgconfig make -j 8
current_install=""
if [ ! -e "$ats_install_path/environment"]; then 
	current_install=`cat $ats_install_path/environment`
fi
echo updating ats_install_path
echo $command
echo $current_install
if [ "$command" == "clean" ] || [ "$current_install" != "$1" ]; then	
	echo deleting $ats_install_path for $1 $2
	# our current install was not same environment, need a complete build
	if [ "$command" == "plugins" ]; then
		command="build"
	fi
	if [ "$ats_install_path" != "" ]; then
		rm -rf $ats_install_path/*
	fi	
fi

mkdir -p $ats_install_path/lib/
cp /usr/lib/x86_64-linux-gnu/libhwloc.so.15 $ats_install_path/lib/
cp /usr/lib/x86_64-linux-gnu/libhwloc.so.15.5.2 $ats_install_path/lib/
ln -sf $ats_install_path/lib/libhwloc.so.15.5.2 $ats_install_path/lib/libhwloc.so.15


printf $1 > $ats_install_path/environment
cp /app/build/$environment/thirdparty-trafficserver/avx-manifest $ats_install_path/ats_9.1.3.deb.manifest
if [ "$command" == "plugins" ]; then
	pushd plugins
	PKG_CONFIG_PATH=/root/.local/lib/pkgconfig make -j 8
	PKG_CONFIG_PATH=/root/.local/lib/pkgconfig make -j 8 install
	popd
else
	PKG_CONFIG_PATH=/root/.local/lib/pkgconfig make -j 8
	PKG_CONFIG_PATH=/root/.local/lib/pkgconfig make -j 8 install
	if [ "$1" == "debug" ] || [ "$arg3" == "test_client" ] || [ "$arg4" == "test_client" ] || [ "$arg5" == "test_client" ] ; then
		cp /app/build/$environment/thirdparty-trafficserver/plugins/experimental/policy_driver/test_client $ats_install_path/bin
		cp /app/build/$environment/thirdparty-trafficserver/plugins/experimental/policy_driver/test_server $ats_install_path/bin
	fi
fi


if [ "$build_deb" == "true" ]; then
	mkdir -p /build
	cd /build


	mkdir $DEB && mkdir -p $DEB/opt/ats && mkdir -p $DEB/lib/systemd/system && mkdir -p $DEB/etc/logrotate.d && mkdir $DEB/DEBIAN && cd $DEB/DEBIAN && \
		printf "package: ats\nversion: 9.1.3\nmaintainer: Kasun\narchitecture: all\ndescription: testing it\n" > control
	mkdir -p /build/$DEB/lib/systemd/system
	mkdir -p /build/$DEB/etc/
	mkdir -p /build/$DEB/DEBIAN

	cp -r /app/source/aviatrix/9_1_3.0001/configs/* ${ats_install_path}/etc/trafficserver 
	cp /app/source/aviatrix/9_1_3.0001/avx-gw-trafficserver.service /build/$DEB/lib/systemd/system 
	cp /app/source/aviatrix/9_1_3.0001/logrotate/avx-gw-trafficserver /build/$DEB/etc/logrotate.d
	cp /app/source/aviatrix/9_1_3.0001/postinst /build/$DEB/DEBIAN
	mkdir -p $ats_install_path/etc/local_ca
	mkdir -p $ats_install_path/var/local_ca/keys
	echo 12345 > $ats_install_path/var/local_ca/serial.txt
	mkdir -p /build/$DEB/opt/ats/

	cp -R $ats_install_path /build/$DEB/opt/ats/
	chown root:root /build/$DEB/DEBIAN/postinst && chmod 0775 /build/$DEB/DEBIAN/postinst
	cd /build/$DEB
	tar cf ../plugin_ats_9.1.3.tgz opt/ats/ats_9.1.3/libexec/trafficserver/avx_certifier.* opt/ats/ats_9.1.3/libexec/trafficserver/policy_driver.*
	cp /build/plugin_ats_9.1.3.tgz /debs
	tar cf ../ats_9.1.3.tgz opt/ats/ats_9.1.3/libexec/* opt/ats/ats_9.1.3/bin/* opt/ats/ats_9.1.3/lib/*
	cp /build/ats_9.1.3.tgz /debs
	cp /app/build/$environment/thirdparty-trafficserver/avx-manifest /debs/ats_9.1.3.deb.manifest
	cd /build	
	

	if [ "$arg3" != "nodeb" ]; then
		time dpkg-deb --build $DEB
		cp /build/ats_9.1.3.deb /debs
	fi	
fi



if [ "$arg3" == "shell" ] || [ "$arg4" == "shell" ] || [ "$arg5" == "shell" ]; then
	cd /app/build/release/thirdparty-trafficserver/plugins/
	bash
fi
