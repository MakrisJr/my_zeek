# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/probabilistic/bloom-filter.bif (alternative mode).

export {
##! Functions to create and manipulate Bloom filters.



module GLOBAL;


## Creates a basic Bloom filter.
##
## fp: The desired false-positive rate.
##
## capacity: the maximum number of elements that guarantees a false-positive
##           rate of *fp*.
##
## name: A name that uniquely identifies and seeds the Bloom filter. If empty,
##       the filter will use :zeek:id:`global_hash_seed` if that's set, and
##       otherwise use a local seed tied to the current Zeek process. Only
##       filters with the same seed can be merged with
##       :zeek:id:`bloomfilter_merge`.
##
## Returns: A Bloom filter handle.
##
## .. zeek:see:: bloomfilter_basic_init2 bloomfilter_counting_init bloomfilter_add
##    bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed
global bloomfilter_basic_init: function(fp: double , capacity: count , name: string &default=""): opaque of bloomfilter ;


## Creates a basic Bloom filter. This function serves as a low-level
## alternative to :zeek:id:`bloomfilter_basic_init` where the user has full
## control over the number of hash functions and cells in the underlying bit
## vector.
##
## k: The number of hash functions to use.
##
## cells: The number of cells of the underlying bit vector.
##
## name: A name that uniquely identifies and seeds the Bloom filter. If empty,
##       the filter will use :zeek:id:`global_hash_seed` if that's set, and
##       otherwise use a local seed tied to the current Zeek process. Only
##       filters with the same seed can be merged with
##       :zeek:id:`bloomfilter_merge`.
##
## Returns: A Bloom filter handle.
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_counting_init  bloomfilter_add
##    bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed
global bloomfilter_basic_init2: function(k: count , cells: count , name: string &default=""): opaque of bloomfilter ;


## Creates a counting Bloom filter.
##
## k: The number of hash functions to use.
##
## cells: The number of cells of the underlying counter vector. As there's
##        no single answer to what's the best parameterization for a
##        counting Bloom filter, we refer to the Bloom filter literature
##        here for choosing an appropriate value.
##
## max: The maximum counter value associated with each element
##      described by *w = ceil(log_2(max))* bits. Each bit in the underlying
##      counter vector becomes a cell of size *w* bits.
##
## name: A name that uniquely identifies and seeds the Bloom filter. If empty,
##       the filter will use :zeek:id:`global_hash_seed` if that's set, and
##       otherwise use a local seed tied to the current Zeek process. Only
##       filters with the same seed can be merged with
##       :zeek:id:`bloomfilter_merge`.
##
## Returns: A Bloom filter handle.
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2 bloomfilter_add
##    bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed
global bloomfilter_counting_init: function(k: count , cells: count , max: count , name: string &default=""): opaque of bloomfilter ;


## Adds an element to a Bloom filter. For counting bloom filters, the counter is incremented.
##
## bf: The Bloom filter handle.
##
## x: The element to add.
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
##    bloomfilter_counting_init bloomfilter_lookup bloomfilter_clear
##    bloomfilter_merge bloomfilter_decrement
global bloomfilter_add: function(bf: opaque of bloomfilter , x: any ): any ;


## Decrements the counter for an element that was added to a counting bloom filter in the past.
##
## Note that decrement operations can lead to false negatives if used on a counting bloom-filter
## that exceeded the width of its counter.
##
## bf: The counting bloom filter handle.
##
## x: The element to decrement
##
## Returns: True on success
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
##    bloomfilter_counting_init bloomfilter_lookup bloomfilter_clear
##    bloomfilter_merge
global bloomfilter_decrement: function(bf: opaque of bloomfilter , x: any ): bool ;



## Retrieves the counter for a given element in a Bloom filter.
##
## For a basic bloom filter, this is 0 when the element is not part of the bloom filter, or 1
## if it is part of the bloom filter.
##
## For a counting bloom filter, this is the estimate of how often an element was added.
##
## bf: The Bloom filter handle.
##
## x: The element to count.
##
## Returns: the counter associated with *x* in *bf*.
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
##    bloomfilter_counting_init bloomfilter_add bloomfilter_clear
##    bloomfilter_merge
global bloomfilter_lookup: function(bf: opaque of bloomfilter , x: any ): count ;


## Removes all elements from a Bloom filter. This function resets all bits in
## the underlying bitvector back to 0 but does not change the parameterization
## of the Bloom filter, such as the element type and the hasher seed.
##
## bf: The Bloom filter handle.
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
##    bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
##    bloomfilter_merge
global bloomfilter_clear: function(bf: opaque of bloomfilter ): any ;


## Merges two Bloom filters.
##
## bf1: The first Bloom filter handle.
##
## bf2: The second Bloom filter handle.
##
## Returns: The union of *bf1* and *bf2*.
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
##    bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
##    bloomfilter_clear bloomfilter_merge
global bloomfilter_merge: function(bf1: opaque of bloomfilter , bf2: opaque of bloomfilter ): opaque of bloomfilter ;


## Intersects two Bloom filters.
##
## The resulting Bloom filter returns true when queried for elements
## that were contained in both bloom filters. Note that intersected Bloom
## filters have a slightly higher probability of false positives than
## Bloom filters created from scratch.
##
## Please note that, while this function works with basic and with counting
## bloom filters, the result always is a basic bloom filter. So - intersecting
## two counting bloom filters will result in a basic bloom filter. The reason
## for this is that there is no reasonable definition of how to handle counters
## during intersection.
##
## bf1: The first Bloom filter handle.
##
## bf2: The second Bloom filter handle.
##
## Returns: The intersection of *bf1* and *bf2*.
##
## .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
##    bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
##    bloomfilter_clear bloomfilter_merge
global bloomfilter_intersect: function(bf1: opaque of bloomfilter , bf2: opaque of bloomfilter ): opaque of bloomfilter ;


## Returns a string with a representation of a Bloom filter's internal
## state. This is for debugging/testing purposes only.
##
## bf: The Bloom filter handle.
##
## Returns: a string with a representation of a Bloom filter's internal state.
global bloomfilter_internal_state: function(bf: opaque of bloomfilter ): string ;

} # end of export section
module GLOBAL;