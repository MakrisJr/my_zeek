# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/smb/smb1_events.bif (plugin mode).

export {
## Generated for all :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` version 1
## messages.
##
## See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
## :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Zeek's
## :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
## both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
## ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
##
## c: The connection.
##
## hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
##
## is_orig: True if the message was sent by the originator of the underlying
##          transport-level connection.
##
## .. zeek:see:: smb2_message
global smb1_message: event(c: connection , hdr: SMB1::Header , is_orig: bool );


## Generated when there is an :abbr:`SMB (Server Message Block)` version 1 response with no message body.
##
## c: The connection.
##
## hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
##
## .. zeek:see:: smb1_message
global smb1_empty_response: event(c: connection , hdr: SMB1::Header );


## Generated for :abbr:`SMB (Server Message Block)` version 1 messages
## that indicate an error. This event is triggered by an :abbr:`SMB (Server Message Block)` header
## including a status that signals an error.
##
## c: The connection.
##
## hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
##
## is_orig: True if the message was sent by the originator of the underlying
##          transport-level connection.
##
## .. zeek:see:: smb1_message
global smb1_error: event(c: connection , hdr: SMB1::Header , is_orig: bool );


} # end of export section
module GLOBAL;
