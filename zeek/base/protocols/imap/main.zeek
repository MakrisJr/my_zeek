
module IMAP;

const ports = { 143/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, ports);
	}

