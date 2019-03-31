@load base/frameworks/netcontrol

redef exit_only_after_terminate = T;

event NetControl::init()
	{
	local netcontrol_broker = NetControl::create_broker(NetControl::BrokerConfig($host=127.0.0.1, $bport=9977/tcp, $topic="bro/event/netcontrol-faucet"), T);
	NetControl::activate(netcontrol_broker, 0);
	}

event NetControl::init_done() &priority=-5
	{
	print "***** NetControl init done!";
	}
 event new_connection(c: connection)
	{
		print "new Connection!";

	}

function drop_connection(c: conn_id, t: interval)
	{
	# As a first step, create the NetControl::Entity that we want to block
	local e = NetControl::Entity($ty=NetControl::CONNECTION, $conn=c);
	# Then, use the entity to create the rule to drop the entity in the forward path
	local r = NetControl::Rule($ty=NetControl::DROP,
		$target=NetControl::FORWARD, $entity=e, $expire=t);

	# Add the rule
	local id = NetControl::add_rule(r);

	if ( id == "" )
		print "Error while dropping";
	}
function allow_connection(c: conn_id, t: interval)
	{
	# As a first step, create the NetControl::Entity that we want to block
	local e = NetControl::Entity($ty=NetControl::CONNECTION, $conn=c);
	# Then, use the entity to create the rule to drop the entity in the forward path
	local r = NetControl::Rule($ty=NetControl::WHITELIST,
		$target=NetControl::FORWARD, $entity=e, $expire=t);

	# Add the rule
	local id = NetControl::add_rule(r);

	if ( id == "" )
		print "Error while whitelisting";
	}	
event connection_established(c: connection)
    {	
		print "Connection established";
		#at brocker subs: response.rule["entity"]
		
		# dropy by ip
		# NetControl::drop_address(c$id$orig_h, 5sec, "hi there");
        # NetControl::whitelist_address(1.2.3.4, 15sec);		

		# direct way to drop by 4tuples
        drop_connection(c$id, 4 secs);

		# direct way to allow by 4tuples
        allow_connection(c$id, 4 secs);

		# NetControl::redirect_flow([$src_h=c$id$orig_h, $src_m = "FF:FF:FF:BB:BB:AA", $src_p=c$id$orig_p, $dst_h=c$id$resp_h, $dst_m="FF:FF:FF:BB:BB:AA", $dst_p=c$id$resp_p], $out_port=5, $t=30sec);
        # NetControl::quarantine_host($infected=c$id$orig_h, $dns=8.8.8.8, $quarantine=127.0.0.3, $t=15sec);
        
    }

event  http_stats (c: connection, stats: http_stats_rec){
		print "http stats";
	}

event icmp_echo_request (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){

		print( c$id$orig_h );
		if ( |NetControl::find_rules_addr(c$id$orig_h)| > 0 )
		{
		print "***** Rule already exists";
		return;
		}

		NetControl::drop_address(c$id$orig_h, 5sec, "***** Hi there");
		print "***** Rule added";
}
event conn_stats (c: connection, os: endpoint_stats, rs: endpoint_stats)
	{
         print "Conn_stats";
	}
event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule added successfully", r$id, msg;
}
