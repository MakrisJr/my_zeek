# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/analyzer/protocol/ssh/events.bif (plugin mode).

export {
## An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
## from the server. This contains an identification string that's used
## for version identification. See :rfc:`4253#section-4.2` for
## details.
##
## c: The connection over which the message was sent.
##
## version: The identification string
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh_server_version: event(c: connection , version: string );


## An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
## from the client. This contains an identification string that's used
## for version identification. See :rfc:`4253#section-4.2` for
## details.
##
## c: The connection over which the message was sent.
##
## version: The identification string
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh_client_version: event(c: connection , version: string );


## This event is generated when an :abbr:`SSH (Secure Shell)`
## connection was determined to have had a successful
## authentication. This determination is based on packet size
## analysis, and errs on the side of caution - that is, if there's any
## doubt about the authentication success, this event is *not* raised.
##
## c: The connection over which the :abbr:`SSH (Secure Shell)`
##    connection took place.
##
## auth_method_none: This is true if the analyzer detected a
##    successful connection before any authentication challenge. The
##    :abbr:`SSH (Secure Shell)` protocol provides a mechanism for
##    unauthenticated access, which some servers support.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh_auth_successful: event(c: connection , auth_method_none: bool );


## This event is generated when an :abbr:`SSH (Secure Shell)`
## connection was determined to have had an authentication attempt.
## This determination is based on packet size analysis, and errs
## on the side of caution - that is, if there's any doubt about
## whether or not an authentication attempt occurred, this event is
## *not* raised.
##
## At this point in the protocol, all we can determine is whether
## or not the user is authenticated. We don't know if the particular
## attempt succeeded or failed, since some servers require multiple
## authentications (e.g. require both a password AND a pubkey), and
## could return an authentication failed message which is marked
## as a partial success.
##
## This event will often be raised multiple times per connection.
## In almost all connections, it will be raised once unless
##
## c: The connection over which the :abbr:`SSH (Secure Shell)`
##    connection took place.
##
## authenticated: This is true if the analyzer detected a
##    successful connection from the authentication attempt.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh_auth_attempted: event(c: connection , authenticated: bool );


## During the initial :abbr:`SSH (Secure Shell)` key exchange, each
## endpoint lists the algorithms that it supports, in order of
## preference. This event is generated for each endpoint, when the
## SSH_MSG_KEXINIT message is seen. See :rfc:`4253#section-7.1` for
## details.
##
## c: The connection over which the :abbr:`SSH (Secure Shell)`
##    connection took place.
##
## cookie: The SSH_MSG_KEXINIT cookie - a random value generated by
##    the sender.
##
## capabilities: The list of algorithms and languages that the sender
##    advertises support for, in order of preference.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh_capabilities: event(c: connection , cookie: string , capabilities: SSH::Capabilities );


## During the :abbr:`SSH (Secure Shell)` key exchange, the server
## supplies its public host key. This event is generated when the
## appropriate key exchange message is seen for SSH2.
##
## c: The connection over which the :abbr:`SSH (Secure Shell)`
##    connection took place.
##
## key: The server's public host key. Note that this is the public key
##    itself, and not just the fingerprint or hash.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_attempted ssh_capabilities
##    ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
##    ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
##    ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init ssh2_gss_init
##    ssh2_rsa_secret
global ssh2_server_host_key: event(c: connection , key: string );


## During the :abbr:`SSH (Secure Shell)` key exchange, the server
## supplies its public host key. This event is generated when the
## appropriate key exchange message is seen for SSH1.
##
## c: The connection over which the :abbr:`SSH (Secure Shell)`
##    connection took place.
##
## p: The exponent for the server's public host key (note this parameter
##    is truly the exponent even though named *p* and the *exponent* parameter
##    will eventually replace it).
##
## e: The prime modulus for the server's public host key (note this parameter
##    is truly the modulus even though named *e* and the *modulus* parameter
##    will eventually replace it).
##
## modulus: The prime modulus of the server's public host key.
##
## exponent: The exponent of the server's public host key.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh1_server_host_key: event(c: connection , modulus: string , exponent: string );


## During the :abbr:`SSH (Secure Shell)` key exchange, the server
## supplies its public host key. This event is generated when the
## appropriate key exchange message is seen for SSH1 or SSH2 and provides
## a fingerprint of the server's host key.
##
## c: The connection over which the :abbr:`SSH (Secure Shell)`
##    connection took place.
##
## hash: an MD5 hash fingerprint associated with the server's host key.
##       For SSH2, this is the hash of the "server public host key" string as
##       seen on the wire in the Diffie-Hellman key exchange reply message
##       (the string itself, excluding the 4-byte length associated with it),
##       which is also the *key* parameter of :zeek:see:`ssh2_server_host_key`
##       For SSH1, this is the hash of the combined multiprecision integer
##       strings representing the RSA1 key's prime modulus and public exponent
##       (concatenated in that order) as seen on the wire,
##       which are also the parameters of :zeek:see:`ssh1_server_host_key`.
##       In either case, the hash is the same "fingerprint" string as presented
##       by other traditional tools, ``ssh``, ``ssh-keygen``, etc, and is the
##       hexadecimal representation of all 16 MD5 hash bytes delimited by colons.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh_server_host_key: event(c: connection , hash: string );


## This event is generated when an :abbr:`SSH (Secure Shell)`
## encrypted packet is seen. This event is not handled by default, but
## is provided for heuristic analysis scripts. Note that you have to set
## :zeek:id:`SSH::disable_analyzer_after_detection` to false to use this
## event. This carries a performance penalty.
##
## c: The connection over which the :abbr:`SSH (Secure Shell)`
##    connection took place.
##
## orig: Whether the packet was sent by the originator of the TCP
##    connection.
##
## len: The length of the :abbr:`SSH (Secure Shell)` payload, in
##    bytes. Note that this ignores reassembly, as this is unknown.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh_encrypted_packet: event(c: connection , orig: bool , len: count );


## Generated if the connection uses a Diffie-Hellman Group Exchange
## key exchange method. This event contains the server DH parameters,
## which are sent in the SSH_MSG_KEY_DH_GEX_GROUP message as defined in
## :rfc:`4419#section-3`.
##
## c: The connection.
##
## p: The DH prime modulus.
##
## q: The DH generator.
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh2_dh_server_params: event(c: connection , p: string , q: string );


## In the event of a GSS-API error on the server, the server MAY send
## send an error message with some additional details. This event is
## generated when such an error message is seen. For more information,
## see :rfc:`4462#section-2.1`.
##
## c: The connection.
##
## major_status: GSS-API major status code.
##
## minor_status: GSS-API minor status code.
##
## err_msg: Detailed human-readable error message
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh2_gss_error: event(c: connection , major_status: count , minor_status: count , err_msg: string );


## The :abbr:`ECDH (Elliptic Curve Diffie-Hellman)` and
## :abbr:`ECMQV (Elliptic Curve Menezes-Qu-Vanstone)` key exchange
## algorithms use two ephemeral key pairs to generate a shared
## secret. This event is generated when either the client's or
## server's ephemeral public key is seen. For more information, see:
## :rfc:`5656#section-4`.
##
## c: The connection.
##
## is_orig: Did this message come from the originator?
##
## q: The ephemeral public key
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh2_ecc_key: event(c: connection , is_orig: bool , q: string );


## The :abbr:`ECDH (Elliptic Curve Diffie-Hellman)` and
## :abbr:`ECMQV (Elliptic Curve Menezes-Qu-Vanstone)` key exchange
## algorithms use two ephemeral key pairs to generate a shared
## secret. This event is generated when either the SSH_MSG_KEX_ECDH_INIT
## or SSH_MSG_ECMQV_INIT message is observed. By definition, these need
## to originate from the client and not from the server.
## For more information, see:
## :rfc:`5656#section-4`.
##
## c: The connection.
##
## is_orig: Did this message come from the originator?
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh2_ecc_init: event(c: connection , is_orig: bool );


## Generated if the connection uses a Diffie-Hellman Group Exchange
## key exchange method. This event contains the direction of the key
## exchange setup, which is indicated by the the SSH_MSG_KEX_DH_GEX_INIT
## message as defined in :rfc:`4419#section-3`.
##
## c: The connection.
##
## is_orig: Did this message come from the originator?
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh2_dh_gex_init: event(c: connection , is_orig: bool );


## In the event of a GSS-API key exchange, this event is raised on
## SSH_MSG_KEXGSS_INIT message.
## For more information see :rfc:`4462#section-2.1`.
##
## c: The connection.
##
## is_orig: Did this message come from the originator?
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh2_gss_init: event(c: connection , is_orig: bool );


## In the event of a GSS-API key exchange, this event is raised on
## SSH_MSG_KEXRSA_PUBKEY message. This message is sent first by the server,
## after which the server will respond with a SSH_MSG_KEXRSA_SECRET message.
## For more information see :rfc:`4432#section-4`.
##
## c: The connection.
##
## is_orig: Did this message come from the originator?
##
## .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
##    ssh_auth_result ssh_auth_successful ssh_auth_attempted
##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
##    ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
##    ssh2_gss_init ssh2_rsa_secret
global ssh2_rsa_secret: event(c: connection , is_orig: bool );

} # end of export section
module GLOBAL;