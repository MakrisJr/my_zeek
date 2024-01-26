# This file was automatically generated by bifcl from option.bif.

export {
##! Definitions of built-in functions that allow the scripting layer to
##! change the value of options and to be notified when option values change.

module Option;




## Set an option to a new value. This change will also cause the option change
## handlers to be called.
##
## ID: The ID of the option to update.
##
## val: The new value of the option.
##
## location: Optional parameter detailing where this change originated from.
##
## Returns: true on success, false when an error occurred.
##
## .. zeek:see:: Option::set_change_handler Config::set_value
##
## .. note:: :zeek:id:`Option::set` only works on one node and does not distribute
##           new values across a cluster. The higher-level :zeek:id:`Config::set_value`
##           supports clusterization and should typically be used instead of this
##           lower-level function.
global Option::set: function(ID: string , val: any , location: string &default=""): bool ;


## Set a change handler for an option. The change handler will be
## called anytime :zeek:id:`Option::set` is called for the option.
##
## ID: The ID of the option for which change notifications are desired.
##
## on_change: The function that will be called when a change occurs. The
##            function can choose to receive two or three parameters: the first
##            parameter is a string containing *ID*, the second parameter is
##            the new option value. The third, optional, parameter is the
##            location string as passed to Option::set. Note that the global
##            value is not yet changed when the function is called. The passed
##            function has to return the new value that it wants the option to
##            be set to. This enables it to reject changes, or change values
##            that are being set. When several change handlers are set for an
##            option they are chained; the second change handler will see the
##            return value of the first change handler as the "new value".
##
## priority: The priority of the function that was added; functions with higher
##           priority are called first, functions with the same priority are
##           called in the order in which they were added.
##
## Returns: true when the change handler was set, false when an error occurred.
##
## .. zeek:see:: Option::set
global Option::set_change_handler: function(ID: string , on_change: any , priority: int &default=0): bool ;


## Helper function that converts a set (of arbitrary index type) to
## a "vector of any".
##
## v: an "any" type corresponding to a set.
##
## Returns: a vector-of-any with one element for each member of v.
global Option::any_set_to_any_vec: function(v: any ): any_vec ;

} # end of export section
module GLOBAL;