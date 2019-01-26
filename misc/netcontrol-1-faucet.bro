event NetControl::init()
	{
	local faucet_plugin = NetControl::create_faucet("");
	NetControl::activate(faucet_plugin, 0);
	}

event connection_established(c: connection)
	{
	NetControl::drop_connection(c$id, 20 secs);
	}
