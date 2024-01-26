# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/file_analysis/analyzer/x509/functions.bif (plugin mode).

export {


## Parses a certificate into an X509::Certificate structure.
##
## cert: The X509 certificate opaque handle.
##
## Returns: A X509::Certificate structure.
##
## .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
##              x509_ext_subject_alternative_name x509_verify
##              x509_get_certificate_string
global x509_parse: function(cert: opaque of x509 ): X509::Certificate ;


## Constructs an opaque of X509 from a der-formatted string.
##
## Note: this function is mostly meant for testing purposes
##
## .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
##              x509_ext_subject_alternative_name x509_verify
##              x509_get_certificate_string x509_parse
global x509_from_der: function(der: string ): opaque of x509 ;


## Returns the string form of a certificate.
##
## cert: The X509 certificate opaque handle.
##
## pem: A boolean that specifies if the certificate is returned
##      in pem-form (true), or as the raw ASN1 encoded binary
##      (false).
##
## Returns: X509 certificate as a string.
##
## .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
##              x509_ext_subject_alternative_name x509_parse x509_verify
global x509_get_certificate_string: function(cert: opaque of x509 , pem: bool &default=F): string ;


## Verifies an OCSP reply.
##
## certs: Specifies the certificate chain to use. Server certificate first.
##
## ocsp_reply: the ocsp reply to validate.
##
## root_certs: A list of root certificates to validate the certificate chain.
##
## verify_time: Time for the validity check of the certificates.
##
## Returns: A record of type X509::Result containing the result code of the
##          verify operation.
##
## .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
##              x509_ext_subject_alternative_name x509_parse
##              x509_get_certificate_string x509_verify
global x509_ocsp_verify: function(certs: x509_opaque_vector , ocsp_reply: string , root_certs: table_string_of_string , verify_time: time &default=network_time()): X509::Result ;


## Verifies a certificate.
##
## certs: Specifies a certificate chain that is being used to validate
##        the given certificate against the root store given in *root_certs*.
##        The host certificate has to be at index 0.
##
## root_certs: A list of root certificates to validate the certificate chain.
##
## verify_time: Time for the validity check of the certificates.
##
## Returns: A record of type X509::Result containing the result code of the
##          verify operation. In case of success also returns the full
##          certificate chain.
##
## .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
##              x509_ext_subject_alternative_name x509_parse
##              x509_get_certificate_string x509_ocsp_verify sct_verify
global x509_verify: function(certs: x509_opaque_vector , root_certs: table_string_of_string , verify_time: time &default=network_time()): X509::Result ;


## Verifies a Signed Certificate Timestamp as used for Certificate Transparency.
## See RFC6962 for more details.
##
## cert: Certificate against which the SCT should be validated.
##
## logid: Log id of the SCT.
##
## log_key: Public key of the Log that issued the SCT proof.
##
## timestamp: Timestamp at which the proof was generated.
##
## hash_algorithm: Hash algorithm that was used for the SCT proof.
##
## issuer_key_hash: The SHA-256 hash of the certificate issuer's public key.
##                  This only has to be provided if the SCT was encountered in an X.509
##                  certificate extension; in that case, it is necessary for validation.
##
## Returns: T if the validation could be performed successfully, F otherwise.
##
## .. zeek:see:: ssl_extension_signed_certificate_timestamp
##              x509_ocsp_ext_signed_certificate_timestamp
##              x509_verify
global sct_verify: function(cert: opaque of x509 , logid: string , log_key: string , signature: string , timestamp: count , hash_algorithm: count , issuer_key_hash: string &default=""): bool ;





## Get the hash of the subject's distinguished name.
##
## cert: The X509 certificate opaque handle.
##
## hash_alg: the hash algorithm to use, according to the IANA mapping at
##           https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
##
## Returns: The hash as a string.
##
## .. zeek:see:: x509_issuer_name_hash x509_spki_hash
##              x509_verify sct_verify
global x509_subject_name_hash: function(cert: opaque of x509 , hash_alg: count ): string ;


## Get the hash of the issuer's distinguished name.
##
## cert: The X509 certificate opaque handle.
##
## hash_alg: the hash algorithm to use, according to the IANA mapping at
##           https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
##
## Returns: The hash as a string.
##
## .. zeek:see:: x509_subject_name_hash x509_spki_hash
##              x509_verify sct_verify
global x509_issuer_name_hash: function(cert: opaque of x509 , hash_alg: count ): string ;


## Get the hash of the Subject Public Key Information of the certificate.
##
## cert: The X509 certificate opaque handle.
##
## hash_alg: the hash algorithm to use, according to the IANA mapping at
##           https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
##
## Returns: The hash as a string.
##
## .. zeek:see:: x509_subject_name_hash x509_issuer_name_hash
##              x509_verify sct_verify
global x509_spki_hash: function(cert: opaque of x509 , hash_alg: count ): string ;


## This function can be used to set up certificate caching. It has to be passed a table[string] which
## can contain any type.
##
## After this is set up, for each certificate encountered, the X509 analyzer will check if the entry
## tbl[sha256 of certificate] is set. If this is the case, the X509 analyzer will skip all further
## processing, and instead just call the callback that is set with
## zeek:id:`x509_set_certificate_cache_hit_callback`.
##
## tbl: Table to use as the certificate cache.
##
## Returns: Always returns true.
##
## .. note:: The base scripts use this function to set up certificate caching. You should only change the
##           cache table if you are sure you will not conflict with the base scripts.
##
## .. zeek:see:: x509_set_certificate_cache_hit_callback
global x509_set_certificate_cache: function(tbl: string_any_table ) : bool ;


## This function sets up the callback that is called when an entry is matched against the table set
## by :zeek:id:`x509_set_certificate_cache`.
##
## f: The callback that will be called when encountering a certificate in the cache table.
##
## Returns: Always returns true.
##
## .. note:: The base scripts use this function to set up certificate caching. You should only change the
##           callback function if you are sure you will not conflict with the base scripts.
##
## .. zeek:see:: x509_set_certificate_cache
global x509_set_certificate_cache_hit_callback: function(f: string_any_file_hook ) : bool ;


## This function checks a hostname against the name given in a certificate subject/SAN, including
## our interpretation of RFC6128 wildcard expansions. This specifically means that wildcards are
## only allowed in the leftmost label, wildcards only span one label, the wildcard has to be the
## last character before the label-separator, but additional characters are allowed before it, and
## the wildcard has to be at least at the third level (so \*.a.b).
##
## hostname: Hostname to test
##
## certname: Name given in the CN/SAN of a certificate; wildcards will be expanded
##
## Returns: True if the hostname matches.
##
## .. zeek:see:: x509_check_cert_hostname
global x509_check_hostname: function(hostname: string , certname: string ): bool ;


## This function checks if a hostname matches one of the hostnames given in the certificate.
##
## For our matching we adhere to RFC6128 for the labels (see :zeek:id:`x509_check_hostname`).
## Furthermore we adhere to RFC2818 and check only the names given in the SAN, if a SAN is present,
## ignoring CNs in the Subject. If no SAN is present, we will use the last CN in the subject
## for our tests.
##
## cert: The X509 certificate opaque handle.
##
## hostname: Hostname to check
##
## Returns: empty string if the hostname does not match; matched name (which can contain wildcards)
##          if it did.
##
## .. zeek:see:: x509_check_hostname
global x509_check_cert_hostname: function(cert_opaque: opaque of x509 , hostname: string ): string ;

} # end of export section
module GLOBAL;