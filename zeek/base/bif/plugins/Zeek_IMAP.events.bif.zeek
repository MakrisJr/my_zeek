# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/imap/events.bif (plugin mode).

export {
## Generated when a server sends a capability list to the client,
## after being queried using the CAPABILITY command.
##
## c: The connection.
##
## capabilities: The list of IMAP capabilities as sent by the server.
global imap_capabilities: event(c: connection , capabilities: string_vec );


## Generated when a IMAP connection goes encrypted after a successful
## StartTLS exchange between the client and the server.
##
## c: The connection.
global imap_starttls: event(c: connection );

} # end of export section
module GLOBAL;
