#!/bin/bash
#################################
# Start by sourceing the script #
# source bro-test.sh            #
#################################

#create faucet ovs network
#Install ovs-docker as here 
#http://containertutorials.com/network/ovs_docker.html

echo "git_bro-netcontrol"
function git_bro-netcontrol(){
	git clone https://github.com/bro/bro-netcontrol.git
}

echo "cr_fuacet-cont"
function cr_faucet-cont(){
         docker run \
                   --rm \
                   --name faucet \
		   -v /etc/faucet/:/etc/faucet/ \
                   -v /var/log/faucet/:/var/log/faucet/ \
                   -p 6653:6653 -p 9302:9302  faucet/faucet  faucet
}
echo "cr_server-cont"
function cr_server-cont(){
	docker run \
                   --rm -it  --name server \
                   --network=none python /bin/bash 
}

echo "cr_host-cont"
function cr_host-cont(){
	docker run \
                   --rm -it --name host \
                   --network=none python  /bin/bash
}
echo "cr_bro-cont"
function cr_bro-cont(){
	docker run \
                   --rm -it --name bro \
                   -v $PWD:/pegler \
                   -v /etc/faucet/:/etc/faucet/ mohmd/bro-ids /bin/bash
}

#sudo docker pull ubuntu
#then install bro on it, save that container as an image for later use. 
#export PATH=/usr/local/bro/bin:$PATH
#export PREFIX=/usr/local/bro
#https://github.com/bro/bro-netcontrol
#export PYTHONPATH=$PREFIX/lib/broctl:/pegler/bro-netcontrol
echo "create_bro_net"
function create_bro_net(){
#	ocker exec -it bro /bin/bash &

	ovs-vsctl add-br ovs-br0 \
	-- set bridge ovs-br0 other-config:datapath-id=0000000000000001 \
	-- set bridge ovs-br0 other-config:disable-in-band=true \
	-- set bridge ovs-br0 fail_mode=secure \
	-- set-controller ovs-br0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

        ip addr add dev ovs-br0 192.168.0.254/24
	ovs-docker add-port ovs-br0 eth0 server --ipaddress=192.168.0.1/24
        ovs-docker add-port ovs-br0 eth0 host --ipaddress=192.168.0.2/24
	ovs-docker add-port ovs-br0 eth1 bro --ipaddress=192.168.0.100/24
}

echo "check_bro_net"
function check_bro_net(){
	ovs-vsctl show 
	ovs-ofctl show ovs-br0
	docker ps
}


# inside dockers
#1- inside bro
# bro -C -i eth1 /pegler/simple-test.bro
#2- then inside another bro terminal 
# python /pegler/simple-client.py

#3- run pyton in python container (box2)
# python -m http.server
#4- run wget inside busybox (box1), just to trigger bro
# wget http://192.168.0.2:8000 | rm index.html

######### Problem!!!!!!!1
# I found that broker send first rule okay, then later I can't receive any in .py file ??, not sure why
#######################################################################################################################333



#if you turn docker containers off their interface will change and then you need to remove and add them again to ovs.
# sudo ovs-docker del-port ovs-br0 eth1 bro

# to REMOVE everything
echo "clear_bro_net_all"
function clear_bro_net_all(){

	docker stop server host bro faucet
	ovs-vsctl del-br ovs-br0
	docker rm server host bro faucet
}

# faucet  reload 
echo "faucet_relaod_config"
function fuacet_reload_config(){
	docker kill --signal=HUP faucet
}


