# This file was automatically generated by bifcl from reporter.bif.

export {
##! The reporter built-in functions allow for the scripting layer to
##! generate messages of varying severity.  If no event handlers
##! exist for reporter messages, the messages are output to stderr.
##! If event handlers do exist, it's assumed they take care of determining
##! how/where to output the messages.
##!
##! See :doc:`/scripts/base/frameworks/reporter/main.zeek` for a convenient
##! reporter message logging framework.

module Reporter;




## Generates an informational message.
##
## msg: The informational message to report.
##
## Returns: Always true.
##
## .. zeek:see:: reporter_info
global Reporter::info: function(msg: string ): bool ;


## Generates a message that warns of a potential problem.
##
## msg: The warning message to report.
##
## Returns: Always true.
##
## .. zeek:see:: reporter_warning
global Reporter::warning: function(msg: string ): bool ;


## Generates a non-fatal error indicative of a definite problem that should
## be addressed. Program execution does not terminate.
##
## msg: The error message to report.
##
## Returns: Always true.
##
## .. zeek:see:: reporter_error
global Reporter::error: function(msg: string ): bool ;


## Generates a fatal error on stderr and terminates program execution.
##
## msg: The error message to report.
##
## Returns: Always true.
global Reporter::fatal: function(msg: string ): bool ;


## Generates a fatal error on stderr and terminates program execution
## after dumping a core file
##
## msg: The error message to report.
##
## Returns: Always true.
global Reporter::fatal_error_with_core: function(msg: string ): bool ;


## Generates a "net" weird.
##
## name: the name of the weird.
##
## Returns: Always true.
global Reporter::net_weird: function(name: string , addl: string &default="", source: string &default=""): bool ;


## Generates a "flow" weird.
##
## name: the name of the weird.
##
## orig: the originator host associated with the weird.
##
## resp: the responder host associated with the weird.
##
## Returns: Always true.
global Reporter::flow_weird: function(name: string , orig: addr , resp: addr , addl: string &default="", source: string &default=""): bool ;


## Generates a "conn" weird.
##
## name: the name of the weird.
##
## c: the connection associated with the weird.
##
## addl: additional information to accompany the weird.
##
## Returns: Always true.
global Reporter::conn_weird: function(name: string , c: connection , addl: string &default="", source: string &default=""): bool ;


## Generates a "file" weird.
##
## name: the name of the weird.
##
## f: the file associated with the weird.
##
## addl: additional information to accompany the weird.
##
## Returns: true if the file was still valid, else false.
global Reporter::file_weird: function(name: string , f: fa_file , addl: string &default="", source: string &default=""): bool ;


## Gets the weird sampling whitelist
##
## Returns: Current weird sampling whitelist
global Reporter::get_weird_sampling_whitelist: function(): string_set ;


## Sets the weird sampling whitelist
##
## whitelist: New weird sampling rate.
##
## Returns: Always true.
global Reporter::set_weird_sampling_whitelist: function(weird_sampling_whitelist: string_set ) : bool ;


## Gets the weird sampling global list
##
## Returns: Current weird sampling global list
global Reporter::get_weird_sampling_global_list: function(): string_set ;


## Sets the weird sampling global list
##
## global_list: New weird sampling rate.
##
## Returns: Always true.
global Reporter::set_weird_sampling_global_list: function(weird_sampling_global_list: string_set ) : bool ;


## Gets the current weird sampling threshold
##
## Returns: current weird sampling threshold.
global Reporter::get_weird_sampling_threshold: function() : count ;


## Sets the current weird sampling threshold
##
## threshold: New weird sampling threshold.
##
## Returns: Always returns true;
global Reporter::set_weird_sampling_threshold: function(weird_sampling_threshold: count ) : bool ;



## Gets the current weird sampling rate.
##
## Returns: weird sampling rate.
global Reporter::get_weird_sampling_rate: function() : count ;


## Sets the weird sampling rate.
##
## weird_sampling_rate: New weird sampling rate.
##
## Returns: Always returns true.
global Reporter::set_weird_sampling_rate: function(weird_sampling_rate: count ) : bool ;


## Gets the current weird sampling duration.
##
## Returns: weird sampling duration.
global Reporter::get_weird_sampling_duration: function() : interval ;


## Sets the current weird sampling duration. Please note that
## this will not delete already running timers.
##
## weird_sampling_duration: New weird sampling duration.
##
## Returns: always returns True
global Reporter::set_weird_sampling_duration: function(weird_sampling_duration: interval ) : bool ;

} # end of export section
module GLOBAL;
