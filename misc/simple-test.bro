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

event connection_established(c: connection)
    {
	# if pcap file (offline traffic) is used then can't receive this drop in simple-client.py, only it gets connectionestablished not the drop rule. 
		print "Connection established";
		NetControl::drop_address(c$id$orig_h, 5sec, "***** Hi there");
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
