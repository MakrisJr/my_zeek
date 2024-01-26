# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/netbios/functions.bif (plugin mode).

export {


## Decode a NetBIOS name.  See https://jeffpar.github.io/kbarchive/kb/194/Q194203/.
##
## name: The encoded NetBIOS name, e.g., ``"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF"``.
##
## Returns: The decoded NetBIOS name, e.g., ``"THE NETBIOS NAM"``.  An empty
##          string is returned if the argument is not a valid NetBIOS encoding
##          (though an encoding that would decode to something that includes
##          only null-bytes or space-characters also yields an empty string).
##
## .. zeek:see:: decode_netbios_name_type
global decode_netbios_name: function(name: string ): string ;


## Converts a NetBIOS name type to its corresponding numeric value.
## See https://en.wikipedia.org/wiki/NetBIOS#NetBIOS_Suffixes.
##
## name: An encoded NetBIOS name.
##
## Returns: The numeric value of *name* or 256 if it's not a valid encoding.
##
## .. zeek:see:: decode_netbios_name
global decode_netbios_name_type: function(name: string ): count ;

} # end of export section
module GLOBAL;
