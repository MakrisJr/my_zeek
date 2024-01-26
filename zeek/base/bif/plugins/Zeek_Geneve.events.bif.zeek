# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/packet_analysis/protocol/geneve/events.bif (plugin mode).

export {
## Generated for any packet encapsulated in a Geneve tunnel.
## See :rfc:`8926` for more information about the Geneve protocol.
##
## outer: The Geneve tunnel connection.
##
## inner: The Geneve-encapsulated Ethernet packet header and transport header.
##
## vni: Geneve Network Identifier.
##
## .. note:: Since this event may be raised on a per-packet basis, handling
##    it may become particularly expensive for real-time analysis.
global geneve_packet: event(outer: connection , inner: pkt_hdr , vni: count );

} # end of export section
module GLOBAL;