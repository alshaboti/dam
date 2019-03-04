event NetControl::init()
	{
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	}

event connection_established(c: connection)
	{
	#NetControl::drop_connection(c$id, 3 secs);
	NetControl::drop_address(1.1.2.2, 3sec, "Hi there");
    NetControl::whitelist_address(1.1.2.2, 3sec);
	}
event http_reply(c: connection, version: string, code: count, reason: string)
	{
		print("http_reply");
	}