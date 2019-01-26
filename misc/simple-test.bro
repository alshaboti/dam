@load base/frameworks/netcontrol

redef exit_only_after_terminate = T;

event NetControl::init()
	{
	local netcontrol_broker = NetControl::create_broker(NetControl::BrokerConfig($host=127.0.0.1, $bport=9977/tcp, $topic="bro/event/netcontrol-example"), T);
	NetControl::activate(netcontrol_broker, 0);
	}

event NetControl::init_done() &priority=-5
	{
	print "Init done";
        # drop rule goes through to simple-client.py
#	NetControl::drop_address(1.1.2.2, 15sec, "Hi there");
	}

event connection_established(c: connection)
    {
   # can't receive this drop in simple-client.py, only it gets connectionestablished not the drop rule!!

    NetControl::drop_address(c$id$resp_h, 15sec, "Hi there");
    }