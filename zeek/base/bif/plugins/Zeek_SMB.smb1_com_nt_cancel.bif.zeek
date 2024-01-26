# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/smb/smb1_com_nt_cancel.bif (plugin mode).

export {
## Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
## version 1 requests of type *nt cancel*. This is sent by the client to request that a currently
## pending request be cancelled.
##
## For more information, see MS-CIFS:2.2.4.65
##
## c: The connection.
##
## hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
##
## .. zeek:see:: smb1_message
global smb1_nt_cancel_request: event(c: connection , hdr: SMB1::Header );
} # end of export section
module GLOBAL;