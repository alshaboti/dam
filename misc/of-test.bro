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
const switch_bro_port: count = 19 &redef;


redef SSH::password_guesses_limit=10;

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == SSH::Password_Guessing)
	# && /192\.168\.0\.1/ in n$sub )
		print "SSH Guessing";
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
	#OpenFlow::flow_clear(of_controller);

	#print "NetControl add flow to mirror packets to bro"
        #OpenFlow::flow_mod(of_controller, [], [$cookie=OpenFlow::generate_cookie(1337), $priority=2, $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(switch_bro_port)]]);
	}

# Shunt all ssl, grid ftp and ssh connections after we cannot get any data from them anymore
event new_connection(c: connection)
	{
	local id = c$id;
        print "New connection event from ", id$orig_h,":", id$orig_p, " to ", id$resp_h, ":", id$resp_p;
	}
event connection_established(c: connection)
	{
        local   id= c$id;
        print "Connection established";
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 5sec);
        #schedule 5 sec { myevent($c=c) };
	}
event myevent(c: connection){
        local   id= c$id;

#       OpenFlow::flow_mod(of_controller, [], [$cookie=OpenFlow::generate_cookie(1337), $priority=2, $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(switch_bro_port)]]);
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);

#	NetControl::drop_connection(c$id, 20 secs);
#	NetControl::drop_address(1.1.2.2, 15sec, "Hi there");
#       NetControl::whitelist_address(1.2.3.4, 15sec);
        print "My event";

 }

function test_mac_flow()
	{
	local flow = NetControl::Flow(
		$src_m = "FF:FF:FF:FF:FF:FF"
	);
	local e: NetControl::Entity = [$ty=NetControl::FLOW, $flow=flow];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

function test_mac()
	{
	local e: NetControl::Entity = [$ty=NetControl::MAC, $mac="FF:FF:FF:FF:FF:FF"];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

function test_all()
	{
	NetControl::shunt_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 30sec);
	NetControl::drop_address(1.1.2.2, 15sec, "Hi there");
	NetControl::whitelist_address(1.2.3.4, 15sec);
	NetControl::redirect_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 5, 30sec);
	NetControl::quarantine_host(127.0.0.2, 8.8.8.8, 127.0.0.3, 15sec);
	test_mac();
	test_mac_flow();
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