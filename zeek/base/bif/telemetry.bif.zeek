# This file was automatically generated by bifcl from /usr/src/packages/BUILD/src/telemetry/telemetry.bif (alternative mode).

export {
##! Functions for accessing counter metrics from script land.

module Telemetry;


type MetricType: enum  {
	DOUBLE_COUNTER,
	INT_COUNTER,
	DOUBLE_GAUGE,
	INT_GAUGE,
	DOUBLE_HISTOGRAM,
	INT_HISTOGRAM,
} ;






global Telemetry::__int_counter_family: function(prefix: string , name: string , labels: string_vec , helptext: string &default = "Zeek Script Metric", unit: string &default = "1", is_sum: bool &default = F): opaque of int_counter_metric_family ;


global Telemetry::__int_counter_metric_get_or_add: function(family: opaque of int_counter_metric_family , labels: table_string_of_string ): opaque of int_counter_metric ;


global Telemetry::__int_counter_inc: function(val: opaque of int_counter_metric , amount: int &default = 1): bool ;


global Telemetry::__int_counter_value: function(val: opaque of int_counter_metric ): int ;




global Telemetry::__dbl_counter_family: function(prefix: string , name: string , labels: string_vec , helptext: string &default = "Zeek Script Metric", unit: string &default = "1", is_sum: bool &default = F): opaque of dbl_counter_metric_family ;


global Telemetry::__dbl_counter_metric_get_or_add: function(family: opaque of dbl_counter_metric_family , labels: table_string_of_string ): opaque of dbl_counter_metric ;


global Telemetry::__dbl_counter_inc: function(val: opaque of dbl_counter_metric , amount: double &default = 1.0): bool ;


global Telemetry::__dbl_counter_value: function(val: opaque of dbl_counter_metric ): double ;




global Telemetry::__int_gauge_family: function(prefix: string , name: string , labels: string_vec , helptext: string &default = "Zeek Script Metric", unit: string &default = "1", is_sum: bool &default = F): opaque of int_gauge_metric_family ;


global Telemetry::__int_gauge_metric_get_or_add: function(family: opaque of int_gauge_metric_family , labels: table_string_of_string ): opaque of int_gauge_metric ;


global Telemetry::__int_gauge_inc: function(val: opaque of int_gauge_metric , amount: int &default = 1): bool ;


global Telemetry::__int_gauge_dec: function(val: opaque of int_gauge_metric , amount: int &default = 1): bool ;


global Telemetry::__int_gauge_value: function(val: opaque of int_gauge_metric ): int ;




global Telemetry::__dbl_gauge_family: function(prefix: string , name: string , labels: string_vec , helptext: string &default = "Zeek Script Metric", unit: string &default = "1", is_sum: bool &default = F): opaque of dbl_gauge_metric_family ;


global Telemetry::__dbl_gauge_metric_get_or_add: function(family: opaque of dbl_gauge_metric_family , labels: table_string_of_string ): opaque of dbl_gauge_metric ;


global Telemetry::__dbl_gauge_inc: function(val: opaque of dbl_gauge_metric , amount: double &default = 1.0): bool ;


global Telemetry::__dbl_gauge_dec: function(val: opaque of dbl_gauge_metric , amount: double &default = 1.0): bool ;


global Telemetry::__dbl_gauge_value: function(val: opaque of dbl_gauge_metric ): double ;




global Telemetry::__int_histogram_family: function(prefix: string , name: string , labels: string_vec , bounds: int_vec , helptext: string &default = "Zeek Script Metric", unit: string &default = "1", is_sum: bool &default = F): opaque of int_histogram_metric_family ;


global Telemetry::__int_histogram_metric_get_or_add: function(family: opaque of int_histogram_metric_family , labels: table_string_of_string ): opaque of int_histogram_metric ;


global Telemetry::__int_histogram_observe: function(val: opaque of int_histogram_metric , measurement: int ): bool ;


global Telemetry::__int_histogram_sum: function(val: opaque of int_histogram_metric ): int ;




global Telemetry::__dbl_histogram_family: function(prefix: string , name: string , labels: string_vec , bounds: double_vec , helptext: string &default = "Zeek Script Metric", unit: string &default = "1", is_sum: bool &default = F): opaque of dbl_histogram_metric_family ;


global Telemetry::__dbl_histogram_metric_get_or_add: function(family: opaque of dbl_histogram_metric_family , labels: table_string_of_string ): opaque of dbl_histogram_metric ;


global Telemetry::__dbl_histogram_observe: function(val: opaque of dbl_histogram_metric , measurement: double ): bool ;


global Telemetry::__dbl_histogram_sum: function(val: opaque of dbl_histogram_metric ): double ;


global Telemetry::__collect_metrics: function(prefix: string , name: string ): any_vec ;


global Telemetry::__collect_histogram_metrics: function(prefix: string , name: string ): any_vec ;

} # end of export section
module GLOBAL;
