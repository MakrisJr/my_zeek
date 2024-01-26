##! The cluster agent boot logic runs in Zeek's supervisor and instructs it to
##! launch a Management agent process. The agent's main logic resides in main.zeek,
##! similarly to other frameworks. The new process will execute that script.
##!
##! If the current process is not the Zeek supervisor, this does nothing.

@load base/utils/paths

@load ./config

# The agent needs the supervisor to listen for node management requests, which
# by default it does not. We need to tell it to do so here, in the agent
# bootstrap code, so the redef applies prior to the fork of the agent process.
redef SupervisorControl::enable_listen = T;

# The Supervisor listens on Broker's default address: any interface. In the
# Management framework there's no need for other machines to interact with
# instance Supervisors directly, so restrict it to listening locally.
redef Broker::default_listen_address = "127.0.0.1";

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = Management::Agent::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
		$addl_base_scripts=vector("policy/frameworks/management/agent/main.zeek"));

	# Establish the agent's working directory. If one is configured
	# explicitly, use as-is if absolute. Otherwise, append it to the state
	# path. Without an explicit directory, fall back to the agent name.
	local statedir = build_path(Management::get_state_dir(), "nodes");

	if ( ! mkdir(statedir) )
		print(fmt("warning: could not create state dir '%s'", statedir));

	if ( Management::Agent::directory != "" )
		sn$directory = build_path(statedir, Management::Agent::directory);
	else
		sn$directory = build_path(statedir, Management::Agent::get_name());

	if ( ! mkdir(sn$directory) )
		print(fmt("warning: could not create agent state dir '%s'", sn$directory));

	# We don't set sn$stdout_file/stderr_file here because the Management
	# framework's Supervisor shim manages those output files itself. See
	# frameworks/management/supervisor/main.zeek for details.

	# This helps identify Management framework nodes reliably.
	sn$env["ZEEK_MANAGEMENT_NODE"] = "AGENT";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create agent node: %s", res));
		exit(1);
		}
	}
