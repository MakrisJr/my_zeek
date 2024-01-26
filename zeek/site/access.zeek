# access.zeek

# Define a record type for Apache access log entries
type ApacheAccessLog: record {
    timestamp: string;
    log_type: string;
    client_ip: addr;
    dash1: string;
    dash2: string;
    timestamp_http: string;
    method: string;
    uri: string;
    http_version: string;
    status_code: int;
    response_size: int;
    dash3: string;
    user_agent: string;
};

# Event handler for processing log entries
event file_new(f: fa_file)
    {
    # Open the file for reading
    local file = open(f$source);

    if (file)
        {
        while (getline(file))
            {
            # Split log entries based on whitespace
            local fields = split_string($0, /\s+/);

            # Check if the log entry is an Apache access log
            if (|fields| >= 14 && fields[6] == "apache-access:")
                {
                # Parse Apache access log entry
                local log_entry: ApacheAccessLog = [
                    $timestamp = fields[0],
                    $log_type = fields[6],
                    $client_ip = to_addr(fields[7]),
                    $dash1 = fields[8],
                    $dash2 = fields[9],
		    $timestamp_http = fields[10] fields[11] fields[12],
                    $method = fields[13],
                    $uri = fields[14],
                    $http_version = fields[15],
                    $status_code = to_int(fields[16]),
                    $response_size = to_int(fields[17]),
                    $dash3 = fields[18],
                    $user_agent = join(fields[19:], " ")
                ];

                print log_entry;
                }
            else
                {
                # Log an error for unexpected log entry format
                print fmt("Unexpected log entry format: %s", $0);
                }
            }

        close(file);
        }
    }

