# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/gssapi/events.bif (plugin mode).

export {
## Generated for GSSAPI negotiation results.
##
## c: The connection.
##
## state: The resulting state of the negotiation.
##
global gssapi_neg_result: event(c: connection , state: count );

} # end of export section
module GLOBAL;