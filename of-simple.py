#!/usr/bin/env python

# Ryu OpenFlow controller that connects to the Bro OpenFlow
# framework using Broker.
#
# Start with ./ryu/bin/ryu-manager controller.py

import logging
import time
import re
import ipaddress
import pprint 

import broker
from select import select

pp = pprint.PrettyPrinter(indent=4)


class BroController(): #app_manager.RyuApp):


    def __init__(self, *args, **kwargs):
        #super(BroController, self).__init__(*args, **kwargs);
        self.queuename = "bro/openflow"
        self.epl = broker.Endpoint()

    def start(self):
        self.epl.listen("127.0.0.1", 9999)
        self.status_subscriber = self.epl.make_status_subscriber(True)
        self.subscriber = self.epl.make_subscriber(self.queuename)

       # thread.start_new_thread(self._broker_loop,(None,))
        try:
           print("Started broker communication...")
           self._broker_loop()
        except Exception as e:
           print ("error", e)

    def _broker_loop(self):
        print("Broker loop...")

        while 1==1:
            print("Waiting for broker message")
            readable, writable, exceptional = select(
                    [self.status_subscriber.fd(), self.subscriber.fd()],
                    [],[])

            if ( self.status_subscriber.fd() in readable ):
                msg = self.status_subscriber.get()
                self.handle_broker_message(msg)
            elif ( self.subscriber.fd() in readable ):
                print("Got broker message")
                msg = self.subscriber.get()
                self.handle_broker_message(msg)

    def handle_broker_message(self, m):
        if isinstance(m, broker.Status):
            if m.code() == broker.SC.PeerAdded:
                print("Connected to bro! ")
                return
            return

        if ( type(m).__name__ != "tuple" ):
            print("Unexpected type %s, expected tuple", type(m).__name__)
            return

        if ( len(m) < 1 ):
            print("Tuple without content?")
            return

        (topic, event) = m
        ev = broker.bro.Event(event)
        event_name = ev.name()
        print()
        print("******* Event name: ",event_name)

        if ( event_name == "OpenFlow::broker_flow_clear" ):
            self.event_flow_clear(ev.args())
        elif ( event_name == "OpenFlow::broker_flow_mod" ):
            self.event_flow_mod(ev.args())
        elif event_name == "OpenFlow::flow_mod_success":
            pass
        elif event_name == "OpenFlow::flow_mod_failure":
            pass
        elif event_name == "OpenFlow::flow_removed":
            pass
        else:
            print("Unknown event %s", event_name)
            return

    def event_flow_clear(self, m):

        # since this is really only a  convenience function we should return it and just do the
        # flow-mod from bro ourselves
        print("** clear flow event len(m)", len(m))
 
        name = m[0]

        dpid = m[1].value
        print("** flow_clear for %s %d", name, dpid)

    def send_success(self, name, match, flow_mod, msg):
        args = [name, match, flow_mod, msg]
        ev = broker.bro.Event("OpenFlow::flow_mod_success", args)
        self.epl.publish(self.queuename, ev)

    def event_flow_mod(self, m):
        print("* flow mod event len(m)", len(m))
        for i in range(len(m)):
            print(" * type(m[i])=", type(m[i]) )
            pp.pprint(m[i])

                                                            
        name = m[0]
        dpid = m[1].value
        match = self.parse_ofp_match(m[2])
        print("* name, dpid: ", name, dpid) 
        print("* MATCH : ", match.items())
 
        try:
            self.send_success(name, m[2], m[3], "")
        except Exception as e:
            print("send success error \n ", e)

    def parse_ofp_match(self, m):
        match = ['in_port', 'dl_src', 'dl_dst', 'dl_vlan', 'dl_vlan_pcp', 'dl_type', 'nw_tos', 'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst']
        return self.record_to_record(match, m)

    def parse_ofp_flow_mod(self, m):
        match = ['cookie', 'table_id', 'command', 'idle_timeout', 'hard_timeout', 'priority', 'out_port', 'out_group', 'flags']

        rec = self.record_to_record(match, m)

        # ok, now we have to get the actions, which are after flags. This is kind of cheating, but... whatever :)
        match_actions = ['out_ports', 'vlan_vid', 'vlan_pcp', 'vlan_strip', 'dl_src', 'dl_dst', 'nw_tos', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst']

        rm = m
        rl = rm[9]
        recaction = self.record_to_record(match_actions, rl.get())
        rec['actions'] = recaction

        return rec

    def record_to_record(self, match, m):


        if not isinstance(m, list):
            self.logger.error("Got non record element")

        rec = m

        dict = {}
        for i in range(0, len(match)):
            if rec[i] is None:
                #dict[match[i]] = None # most of the functions expect this to be undefined, not none. We oblige.
                continue

            dict[match[i]] = self.convert_element(rec[i])

        return dict

    def convert_element(self, el):
        if isinstance(el, broker.Count):
            return el.value

        if isinstance(el, ipaddress.IPv4Address):
            return str(el);

        if isinstance(el, ipaddress.IPv6Address):
            return str(el);

        if isinstance(el, ipaddress.IPv4Network):
            return str(el);

        if isinstance(el, ipaddress.IPv6Network):
            return str(el);

        if isinstance(el, broker.Port):
            p = str(el)
            ex = re.compile('([0-9]+)(.*)')
            res = ex.match(p)
            return (res.group(1), res.group(2))

        if isinstance(el, broker.Enum):
            tmp = el.name
            return re.sub(r'.*::', r'', tmp)

        if isinstance(el, list):
            return [convertElement(ell) for ell in el];

        if isinstance(el, datetime.datetime):
            return el

        if isinstance(el, datetime.timedelta):
            return el

        if isinstance(el, int):
            return el

        if isinstance(el, str):
            return el

        logger.error("Unsupported type %s", type(el) )
        return el;  


x = BroController()
x.start()
