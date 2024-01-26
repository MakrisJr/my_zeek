# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/packet_analysis/protocol/vxlan/events.bif (plugin mode).

export {
## Generated for any packet encapsulated in a VXLAN tunnel.
## See :rfc:`7348` for more information about the VXLAN protocol.
##
## outer: The VXLAN tunnel connection.
##
## inner: The VXLAN-encapsulated Ethernet packet header and transport header.
##
## vni: VXLAN Network Identifier.
##
## .. note:: Since this event may be raised on a per-packet basis, handling
##    it may become particularly expensive for real-time analysis.
global vxlan_packet: event(outer: connection , inner: pkt_hdr , vni: count );

} # end of export section
module GLOBAL;
