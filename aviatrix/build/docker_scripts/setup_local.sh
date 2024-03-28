#!/bin/bash
export ats_install_path=/opt/ats/ats_local_debug
export configure_with="--with-user=ubuntu --enable-debug --with-openssl=$OPENSSL --enable-tproxy --prefix=$ats_install_path --disable-dependency-checking --enable-example-plugins --enable-experimental-plugins"
export build_deb=false

function apply_netmask {
    # Parse IP and netmask from input
    ip=$(echo "$1" | cut -d/ -f1)
    netmask=$(echo "$1" | cut -d/ -f2)
    
    # Convert netmask to bitmask
    bitmask=$((0xffffffff << (32 - netmask)))
    
    # Convert IP address to integer
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    int=$((i1 * 256 ** 3 + i2 * 256 ** 2 + i3 * 256 + i4))
    
    # Apply bitmask to integer
    masked_int=$((int & bitmask))
    
    # Convert masked integer back to IP address
    masked_ip=$(printf "%d.%d.%d.%d" \
        $((masked_int >> 24)) \
        $((masked_int >> 16 & 255)) \
        $((masked_int >> 8 & 255)) \
        $((masked_int & 255)))
    
    # Return masked IP address
    echo "$masked_ip/$netmask"
}


function setupnet {
    local ns=$1
    local veth1=$2
    local veth2=$4
    local ip1=$3
    local ip2=$5
    local cleanip1=$(printf $3 | sed -r 's#(.*)/.*#\1#')
    local cleanip2=$(printf $4 | sed -r 's#(.*)/.*#\1#')
    local cleanroutenetmask=$(apply_netmask $3)
    echo $ns $veth1 $veth2 $ip1 $ip2 $cleanip1 $cleanip2
    # create network namespace
    ip netns add $ns
    # create interfaces
    ip link add $veth1 type veth peer name $veth121
    # set outside interface ip address
    ip addr add $ip1 dev $veth1
    # up outside facing interface
    ip link set $veth1 up
    # move inner interface to network namespace
    ip link set $veth2 netns $ns    
    # set ip address
    ip netns exec $ns ip addr add $ip2 dev $veth2
    # ip inner interface
    ip netns exec $ns ip link set $veth2 up
    # add the route for the inner network
    ip route add $cleanroutenetmask dev $veth1
    # add the default route for the network namespace to the outside
    ip netns exec $ns ip route add default via $cleanip1 dev $veth2 onlink

} 

setupnet "net1011" "veth111" "10.11.0.1/24" "veth112" "10.11.0.2/24"
setupnet "net1012" "veth121" "10.12.0.1/24" "veth122" "10.12.0.2/24"




echo '
escape ^Xa
# skip the startup message
startupmessage off

# Display a caption string below, appearing like tabs and
# displaying the window number and application name (by default).
caption always
caption string "Use ctrl-x as screen key %{kw}%-w%{wr}%n %t%{-}%+w"
#
# j to move down a window, k to move up. Like teh VIM!
bind j focus down
bind k focus up
bind > focus next
bind < focus prev
#
# Default screens
screen -t main
screen -t net1011
screen -t net1012   ls ; bash
screen -t nginx1012
#
# Select first screen
select 0
' >  ~/.screenrc