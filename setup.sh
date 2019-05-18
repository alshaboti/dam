#!/bin/bash
#################################
# Start by sourceing the script #
# source bro-test.sh            #
#################################

#create faucet ovs network
#Install ovs-docker as here 
#http://containertutorials.com/network/ovs_docker.html
echo ">>>>>>>>>>>>>>>Pre requisits<<<<<<<<<<<<<<<<<<<<<"


# echo "git_zeek-netcontrol"
# function git_zeek-netcontrol(){
# 	git clone https://github.com/zeek/zeek-netcontrol.git
# }

# echo "git_faucetagent"
# function git_faucetagent()
# {
#      git clone https://github.com/faucetsdn/faucetagent.git
#      # remove sudo, as faucet container will run as root
# #     cd faucetagent
# #     sed -i "s/sudo//g" dependencies.sh
# }

echo "generate_gNMI_certs"
function generate_gNMI_certs(){
	mkdir -p tls_cert_key
	mkdir -p tls_cert_key/server
	openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout tls_cert_key/server/server.key -out tls_cert_key/server/server.crt  -subj '/CN=faucet.localhost'
	mkdir -p tls_cert_key/client
	openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout tls_cert_key/client/client.key -out tls_cert_key/client/client.crt  -subj '/CN=bro.localhost'
        cp tls_cert_key/server/server.crt tls_cert_key/client/ca.crt
}

echo "############## First: Create and attach to each container ##################### "
echo "1- Either use tmux and create and attach to each container using the following functions"
echo "cr_faucet-cont"
function cr_faucet-cont(){
                   docker run \
		   --rm --name faucet \
                   -v /var/log/faucet/:/var/log/faucet/ \
                   -v $PWD/etc/faucet/:/etc/faucet/ \
                   -p 6653:6653 -p 9302:9302 \
		   mohmd/faucet-ssh
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

echo "2- OR create and attach to all container at once using xterm"
echo "cr_all_conts_with_xterms"
function cr_all_conts_with_xterms(){
	xterm -T faucet -e  \
                    docker run \
		   --rm --name faucet \
                   -v /var/log/faucet/:/var/log/faucet/ \
                   -v $PWD/etc/faucet/:/etc/faucet/ \
				   -v $PWD/tls_cert_key/:/pegler/tls_cert_key/ \
                   -p 6653:6653 -p 9302:9302 \
                    mohmd/faucet-ssh  	&
	#bash -c "/usr/sbin/sshd -D ; faucet" &
		   #mohmd/faucet-ssh bash -c "/etc/init.d/ssh start && faucet" &
		  


	xterm -bg MediumPurple4 -T host -e \
                   docker run \
                   --rm  --name host \
                   -it \
                   python bash &

	xterm -bg NavyBlue -T server -e \
                   docker run \
                   --rm --name server \
                   -it \
                   python bash &

	xterm -bg Maroon -T broIDS -e \
                   docker run \
                   --rm  --name bro \
                   -it \
		   -v $PWD/src/:/pegler/src/ \
		   -v $PWD/tls_cert_key/:/pegler/tls_cert_key/ \
                   -w /pegler/src \
         	   mohmd/bro-ids /bin/bash &
}


#docker pull ubuntu
#then install bro on it, save that container as an image for later use. 
#export PATH=/usr/local/bro/bin:$PATH
#export PREFIX=/usr/local/bro
#https://github.com/bro/bro-netcontrol
#export PYTHONPATH=$PREFIX/lib/broctl:/pegler/bro-netcontrol
echo "###################### Second: configure and build the network connections ####################"
echo "create_bro_net"
function create_bro_net(){
	ovs-vsctl add-br ovs-br0 \
	-- set bridge ovs-br0 other-config:datapath-id=0000000000000001 \
	-- set bridge ovs-br0 other-config:disable-in-band=true \
	-- set bridge ovs-br0 fail_mode=secure \
	-- set-controller ovs-br0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

	# create bridge btween bro and faucet
	docker network create --subnet 192.168.100.0/24 --driver bridge bro_faucet_nw 1>/dev/null
	docker network connect --ip 192.168.100.2 bro_faucet_nw bro 
	docker network connect --ip 192.168.100.3 bro_faucet_nw faucet

    # connect the rest to ovs-br0
	ip addr add dev ovs-br0 192.168.0.254/24
	ovs-docker add-port ovs-br0 eth1 server --ipaddress=192.168.0.1/24
	ovs-docker add-port ovs-br0 eth1 host --ipaddress=192.168.0.2/24
	ovs-docker add-port ovs-br0 eth2 bro --ipaddress=192.168.0.100/24
}


echo "######################### Third (optinal): you may use other commands #########################"
echo "check_bro_net"
function check_bro_net(){
	ovs-vsctl show 
	ovs-ofctl show ovs-br0
	docker ps
}


echo "get_bro-bash"
function get_bro-bash(){
	docker exec -it bro -w /pegler/ /bin/bash
}
echo "get_bro-bash-xterm"
function get_bro-bash-xterm(){
	xterm -T broXterm -bg Maroon -e docker exec -it -w /pegler/ bro /bin/bash &
}
echo "get_faucet-bash-xterm"
function get_faucet-bash-xterm(){
	xterm -T faucetXterm -e docker exec -it  faucet /bin/bash &
}
# faucet  reload 
echo "faucet_relaod_config"
function fuacet_reload_config(){
	docker kill --signal=HUP faucet
}



echo "################### Remove everything ########################"
# to REMOVE everything
echo "clear_bro_net_all"
function clear_bro_net_all(){
	docker stop server host bro faucet 2>/dev/null
	ovs-vsctl del-br ovs-br0 2>/dev/null
	docker rm host server bro faucet  2>/dev/null
	docker network rm bro_faucet_nw 2>/dev/null
}


