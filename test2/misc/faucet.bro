# later you need to move it into bro/share/bro/base/frameworks/netcontrol/plugins
# also update the __load__.bro in plugins to load faucet.bro as well.

module NetControl;

export {
    global create_faucet: function(argument: string): PluginState;
}

function faucet_name(p: PluginState) : string
{
    return "NetControl Faucet controller plugin"; 
}

function faucet_add_rule_fun(p: PluginState, r: Rule): bool
{
    print "Faucet will try to install the rule", r;
    event NetControl::rule_added(r, p);
    return T;
}


function faucet_remove_rule_fun(p: PluginState, r: Rule, reason: string &default=""): bool
{
    print "Faucet will try to remove rule ", r;
    event NetControl::rule_removed(r, p);
    return T;
}

global faucet_plugin = Plugin(
	$name = faucet_name,
	$can_expire = F,
	$add_rule = faucet_add_rule_fun,
	$remove_rule = faucet_remove_rule_fun
	);

function create_faucet(argument: string) : PluginState
{
    local p = PluginState($plugin = faucet_plugin);
    return p;
}
