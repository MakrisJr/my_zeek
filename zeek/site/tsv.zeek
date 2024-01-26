type Idx: record {
    timestamp: time;
    # other fields...
};

type Val: record {
    ip: addr;
    request: string;
    # other fields...
};

global file_source = "/home/anthos/Documents/Honours/detgen/captures/capture-260-XXE-rsyslog/logs/test.tsv";

global access_list: table[string] of Val = table();

# Function to convert ISO 8601 timestamp to Unix time
function iso8601_to_unix_time(ts: string): time {
    return strptime(ts, "%Y-%m-%dT%H:%M:%S%z");
}

event zeek_init() {
    Input::add_table([$source=file_source,
                      $name="hosts",
                      $idx=Idx,
                      $val=Val,
                      $destination=access_list,
    ]);

    Input::remove("hosts");
}

event zeek_done() {
    # Print the contents of the access_list table
    print "Access List Table:";
    for (key in access_list) {
        print key, " -> ", access_list[key];
    }
}

