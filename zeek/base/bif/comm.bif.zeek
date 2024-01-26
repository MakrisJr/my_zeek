# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/broker/comm.bif (alternative mode).

export {

##! Functions and events regarding broker communication mechanisms.



module Broker;


## Generated when something changes in the Broker sub-system.
global Broker::status: event(endpoint: EndpointInfo , msg: string );


## Generated when a new peering has been established.
global Broker::peer_added: event(endpoint: EndpointInfo , msg: string );


## Generated when an existing peer has been removed.
global Broker::peer_removed: event(endpoint: EndpointInfo , msg: string );


## Generated when an existing peering has been lost.
global Broker::peer_lost: event(endpoint: EndpointInfo , msg: string );


## Generated when a new Broker endpoint appeared.
global Broker::endpoint_discovered: event(endpoint: EndpointInfo , msg: string );


## Generated when the last path to a Broker endpoint has been lost.
global Broker::endpoint_unreachable: event(endpoint: EndpointInfo , msg: string );


## Generated when an error occurs in the Broker sub-system.
global Broker::error: event(code: ErrorCode , msg: string );


## Enumerates the possible error types.
type ErrorCode: enum  {
	NO_ERROR = 0,
	UNSPECIFIED = 1,
	PEER_INCOMPATIBLE = 2,
	PEER_INVALID = 3,
	PEER_UNAVAILABLE = 4,
	PEER_DISCONNECT_DURING_HANDSHAKE = 5,
	PEER_TIMEOUT = 6,
	MASTER_EXISTS = 7,
	NO_SUCH_MASTER = 8,
	NO_SUCH_KEY = 9,
	REQUEST_TIMEOUT = 10,
	TYPE_CLASH = 11,
	INVALID_DATA = 12,
	BACKEND_FAILURE = 13,
	STALE_DATA = 14,
	CANNOT_OPEN_FILE = 15,
	CANNOT_WRITE_FILE = 16,
	INVALID_TOPIC_KEY = 17,
	END_OF_FILE = 18,
	INVALID_TAG = 19,
	INVALID_STATUS = 20,
	CAF_ERROR = 100,
} ;


type PeerStatus: enum  {
	INITIALIZING,
	CONNECTING,
	CONNECTED,
	PEERED,
	DISCONNECTED,
	RECONNECTING,
} ;


type BrokerProtocol: enum  {
	NATIVE,
	WEBSOCKET,
} ;


global Broker::__listen: function(a: string , p: port , proto: BrokerProtocol ): port ;


global Broker::__peer: function(a: string , p: port , retry: interval ): bool ;


global Broker::__peer_no_retry: function(a: string , p: port ): bool ;


global Broker::__unpeer: function(a: string , p: port ): bool ;


global Broker::__peers: function(): PeerInfos ;


global Broker::__node_id: function(): string ;


global Broker::__set_metrics_export_interval: function(value: interval ): bool ;


global Broker::__set_metrics_export_topic: function(value: string ): bool ;


global Broker::__set_metrics_import_topics: function(filter: string_vec ): bool ;


global Broker::__set_metrics_export_endpoint_name: function(value: string ): bool ;


global Broker::__set_metrics_export_prefixes: function(filter: string_vec ): bool ;

} # end of export section
module GLOBAL;