@load base/protocols/conn
@load protocols/ssh/detect-bruteforcing
@load base/frameworks/openflow
@load base/frameworks/netcontrol

const broker_port: port = 9999/tcp &redef;
global of_controller: OpenFlow::Controller;
global myevent: event(c: connection);

# Switch datapath ID
const switch_dpid: count = 0 &redef;

# port on which Bro is listening - we install a rule to the switch to mirror traffic here...
const switch_bro_port: count = 3 &redef;

redef SSH::password_guesses_limit=3;

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == SSH::Password_Guessing)
	# && /192\.168\.0\.1/ in n$sub )
	    local id = n$id;
		print n$msg;	
		print "SSH Guessing", id$orig_h,":", id$orig_p, " to ", id$resp_h, ":", id$resp_p;
	}

event NetControl::init() &priority=2
	{
	of_controller = OpenFlow::broker_new("of", 127.0.0.1, broker_port, "bro/openflow", switch_dpid);
	local pacf_of = NetControl::create_openflow(of_controller, NetControl::OfConfig($monitor=T, $forward=F, $priority_offset=+5));
	NetControl::activate(pacf_of, 0);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer connected", endpoint$network;
	}

event NetControl::init_done()
	{
	print "NeControl is starting operations";
	}



###########################################################################################################

function test_mac_flow()
	{
	local flow = NetControl::Flow(
		$src_m = "FF:FF:FF:AA:AA:BB"
	);
	local e: NetControl::Entity = [$ty=NetControl::FLOW, $flow=flow];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

function test_mac()
	{
	local e: NetControl::Entity = [$ty=NetControl::MAC, $mac="FF:FF:FF:BB:BB:AA"];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

function test_netControl(c: connection)
{
	
    local id= c$id;
	
	#print "drop_address sent.";
    #NetControl::drop_address(1.1.2.2, 15sec, "Hi there"); # not received in the python

	# print "drop_connection sent..";
    # NetControl::drop_connection(c$id, 20 secs);

	print "shunt_flow sent..";
    NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], $t=30sec);

	# print "redirect_flow sent..";
    # NetControl::redirect_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], $out_port=5, $t=30sec);

	# print "quarantine_host sent..";
    # NetControl::quarantine_host($infected=id$orig_h, $dns=8.8.8.8, $quarantine=127.0.0.3, $t=15sec);

	# print "whitelist_address sent..";
    # NetControl::whitelist_address(1.2.3.4, 15sec);	
    test_mac_flow();
	test_mac();
}

function test_openflow(c: connection)
{
	
    local id= c$id;
	OpenFlow::flow_clear(of_controller);
    #event received as OpenFlow::broker_flow_clear   
    # look https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/main.bro.html#id-OpenFlow::flow_mod
	# in_port, dl_src, dl_dst,dl_vlan,dl_vlan_pcp,dl_type,nw_tos,nw_proto,nw_src
	# ,nw_dst,tp_src,tp_dst
	print id$orig_h;
	local ofm: OpenFlow::ofp_match = [$in_port=3, $nw_src= id$orig_h/24, $nw_dst = id$resp_h/24];
	print ofm;
    OpenFlow::flow_mod(of_controller, ofm, [$cookie=OpenFlow::generate_cookie(1337), $priority=2, $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(switch_bro_port)]]);
}

event myevent(c: connection){
    local   id= c$id;
    print "My event";

 }

###############################################################

event new_connection(c: connection)
	{
	#local id = c$id;
    #print "New connection event from ", id$orig_h,":", id$orig_p, " to ", id$resp_h, ":", id$resp_p;
	}

event connection_established(c: connection)
	{
        # https://docs.zeek.org/en/stable/scripts/base/init-bare.bro.html#type-conn_id
        print "Connection established .... c$service = ";        

        print "OpenFlow both clear and mod are working .";
		# print "OpenFlow::ofp_match match with subnet nw_src and not with host!!!"
		#test_openflow($c=c);

		print "NETCONTROL only shunt_flow works, the others are not received in the python script.";
		test_netControl($c = c);
        #schedule 5 sec { myevent($c=c) };
	}



###############################33

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule added successfully", r$id;
	}

event NetControl::rule_error(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule error", r$id, msg;
	}

event NetControl::rule_timeout(r: NetControl::Rule, i: NetControl::FlowInfo, p: NetControl::PluginState)
	{
	print "Rule timeout", r$id, i;
	}

event OpenFlow::flow_mod_success(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	print "Flow mod success";
	}

event OpenFlow::flow_mod_failure(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	print "Flow mod failure", flow_mod$cookie, msg;
	}

event OpenFlow::flow_removed(name: string, match: OpenFlow::ofp_match, cookie: count, priority: count, reason: count, duration_sec: count, idle_timeout: count, packet_count: count, byte_count: count)
	{
	print "Flow removed", match;
	}
