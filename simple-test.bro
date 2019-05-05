@load base/frameworks/netcontrol
@load base/files/extract

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
function drop_allow_NetControl(id: conn_id, t: interval, action: string)	
{
	# dropy by ip
	if(action == "drop")
		NetControl::drop_address(id$orig_h, 5sec, "hi there");
	# else if(action == "whitelist")				
	# 	NetControl::whitelist_address(1.2.3.4, 15sec);		
	# else if(action == "redirect")				
	# 	NetControl::redirect_flow([$src_h=c$id$orig_h, $src_m = "FF:FF:FF:BB:BB:AA", $src_p=c$id$orig_p, $dst_h=c$id$resp_h, $dst_m="FF:FF:FF:BB:BB:AA", $dst_p=c$id$resp_p], $out_port=5, $t=30sec);
	# else if(action == "quarantine")				
	# 	NetControl::quarantine_host($infected=c$id$orig_h, $dns=8.8.8.8, $quarantine=127.0.0.3, $t=15sec);

}
# event connection_established(c: connection)
#     {	
# 		print "Connection established";
# 		#at brocker subs: response.rule["entity"]

# 		# direct way to drop by 4tuples
#         #drop_connection(c$id, 4 secs);

# 		# direct way to allow by 4tuples
#         #allow_connection(c$id, 4 secs);
        
#     }

# event  http_stats (c: connection, stats: http_stats_rec){
# 		#print "http stats";
# 	}

# event icmp_echo_request (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){

# 		print( c$id$orig_h );
# 		if ( |NetControl::find_rules_addr(c$id$orig_h)| > 0 )
# 		{
# 		print "***** Rule already exists";
# 		return;
# 		}

# 		NetControl::drop_address(c$id$orig_h, 5sec, "***** Hi there");
# 		print "***** Rule added";
# }
# event conn_stats (c: connection, os: endpoint_stats, rs: endpoint_stats)
# 	{
#          print "Conn_stats";
# 	}
event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Rule added successfully", r$id, msg;
}


########## file analysis framework ######
# event file_new(f: fa_file)
#     {
#     local ext = "";
#     #print f;
#     # if ( f?$mime_type )
#     #     ext = ext_map[f$mime_type];

#     local fname = fmt("%s-%s", f$source, f$id);
# 	print fname;
#     #Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
#     }

#https://docs.zeek.org/en/latest/scripts/base/bif/event.bif.zeek.html#id-file_new
event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
{
 #print "All connections: ", f$conns;
 print "This connection: ", c$id;

}

#fa_file record: https://docs.zeek.org/en/stable/scripts/base/init-bare.bro.html#type-fa_file
event file_sniff(f: fa_file, meta: fa_metadata)
    {
	#print "file_sniff";
	#print meta ;
	if ( ! meta?$mime_type ) return;
    #print "new file", f$id, meta$mime_type;

	#text/html, application/x-sharedlib
    if ( meta$mime_type == "application/x-executable" ) 
        Files::add_analyzer(f, Files::ANALYZER_MD5);		
    }
event file_hash(f: fa_file, kind: string, hash: string)
    {
     print "file_hash", f$id, kind, hash;

	if (kind== "md5" && hash == "8e5b325156981e0bcba714dc32f718c5" ){
		print "Bash binary file md5!";
		for ( cid in f$conns )
		{
			#print f$conns[cid]$uid;
			print "Rule is sent to drop connection: ", cid;
			drop_connection(cid, 5 secs);
		}		
	}

    print "service ", f$source;
    }