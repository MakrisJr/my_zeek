# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/probabilistic/cardinality-counter.bif (alternative mode).

export {
##! Functions to create and manipulate probabilistic cardinality counters.



module GLOBAL;


## Initializes a probabilistic cardinality counter that uses the HyperLogLog
## algorithm.
##
## err: the desired error rate (e.g. 0.01).
##
## confidence: the desired confidence for the error rate (e.g., 0.95).
##
## Returns: a HLL cardinality handle.
##
## .. zeek:see:: hll_cardinality_estimate hll_cardinality_merge_into hll_cardinality_add
##    hll_cardinality_copy
global hll_cardinality_init: function(err: double , confidence: double ): opaque of cardinality ;


## Adds an element to a HyperLogLog cardinality counter.
##
## handle: the HLL handle.
##
## elem: the element to add.
##
## Returns: true on success.
##
## .. zeek:see:: hll_cardinality_estimate hll_cardinality_merge_into
##    hll_cardinality_init hll_cardinality_copy
global hll_cardinality_add: function(handle: opaque of cardinality , elem: any ): bool ;


## Merges a HLL cardinality counter into another.
##
## .. note:: The same restrictions as for Bloom filter merging apply,
##    see :zeek:id:`bloomfilter_merge`.
##
## handle1: the first HLL handle, which will contain the merged result.
##
## handle2: the second HLL handle, which will be merged into the first.
##
## Returns: true on success.
##
## .. zeek:see:: hll_cardinality_estimate  hll_cardinality_add
##    hll_cardinality_init hll_cardinality_copy
global hll_cardinality_merge_into: function(handle1: opaque of cardinality , handle2: opaque of cardinality ): bool ;


## Estimate the current cardinality of an HLL cardinality counter.
##
## handle: the HLL handle.
##
## Returns: the cardinality estimate. Returns -1.0 if the counter is empty.
##
## .. zeek:see:: hll_cardinality_merge_into hll_cardinality_add
##    hll_cardinality_init hll_cardinality_copy
global hll_cardinality_estimate: function(handle: opaque of cardinality ): double ;


## Copy a HLL cardinality counter.
##
## handle: cardinality counter to copy.
##
## Returns: copy of handle.
##
## .. zeek:see:: hll_cardinality_estimate hll_cardinality_merge_into hll_cardinality_add
##    hll_cardinality_init
global hll_cardinality_copy: function(handle: opaque of cardinality ): opaque of cardinality ;

} # end of export section
module GLOBAL;