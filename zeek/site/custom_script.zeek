# custom_apache_logs.zeek

# Define a record type for Apache error log entries
type ApacheErrorLog: record {
    timestamp: string;
    log_type: string;
    error_message: string;
};

# Define a record type for Apache access log entries
type ApacheAccessLog: record {
    timestamp: string;
    log_type: string;
    client_ip: addr;
    method: string;
    uri: string;
    status_code: int;
    user_agent: string;
};

# Load the input framework for reading log files
# @load Files

# Event handler for processing log entries
event file_log(f: fa_file, meta: fa_metadata, data: string)
    {
    # Split log entries based on whitespace
    local fields = split_string(data, /\s+/);

    # Check if the log entry is an Apache error log
    if (|fields| >= 10 && fields[6] == "apache-error:")
        {
        # Parse Apache error log entry
	local log_entry_err: ApacheErrorLog = [
	    $timestamp = fields[0],
	    $log_type = fields[6],
	    $error_message = fmt("%s", fields[11:|fields| - 1]) + " "
	];




        print log_entry_err;
        }
    # Check if the log entry is an Apache access log
    else if (|fields| >= 12 && fields[6] == "apache-access:")
        {
        # Parse Apache access log entry
        local log_entry: ApacheAccessLog = [
            $timestamp = fields[0],
            $log_type = fields[6],
            $client_ip = to_addr(fields[7]),
            $method = fields[10],
            $uri = fields[11],
            $status_code = to_int(fields[12]),
            $user_agent = fmt("%s", fields[15:|fields| - 1]) + " "
        ];

        print log_entry;
        }
    else
        {
        # Log an error for unexpected log entry format
        print fmt("Unexpected log entry format: %s", data);
        }
    }
