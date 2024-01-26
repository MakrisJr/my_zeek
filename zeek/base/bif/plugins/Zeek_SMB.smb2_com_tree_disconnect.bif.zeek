# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/smb/smb2_com_tree_disconnect.bif (plugin mode).

export {
## Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
## version 2 requests of type *tree disconnect*. This is sent by the client to logically disconnect
## client access to a server resource.
##
## c: The connection.
##
## hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
##
## .. zeek:see:: smb2_message
global smb2_tree_disconnect_request: event(c: connection , hdr: SMB2::Header );



## Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
## version 2 requests of type *tree disconnect*. This is sent by the server to logically disconnect
## client access to a server resource.
##
## c: The connection.
##
## hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
##
## .. zeek:see:: smb2_message
global smb2_tree_disconnect_response: event(c: connection , hdr: SMB2::Header );

} # end of export section
module GLOBAL;