# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/smb/smb1_com_transaction2_secondary.bif (plugin mode).

export {
## Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
## version 1 requests of type *transaction2 secondary*.
##
## For more information, see MS-CIFS:2.2.4.47.1
##
## c: The connection.
##
## hdr: The parsed header of the :abbr:`SMB (Server Message Block)`
##      version 1 message.
##
## args: arguments of the message (SMB_Parameters.Words)
##
## parameters: content of the SMB_Data.Trans_Parameters field
##
## data: content of the SMB_Data.Trans_Data field
global smb1_transaction2_secondary_request: event(c: connection , hdr: SMB1::Header , args: SMB1::Trans2_Sec_Args , parameters: string , data: string );


### Types

} # end of export section
module GLOBAL;