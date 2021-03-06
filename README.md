# vmware_sdwan_event

Splunk VeloCloud Event Log - Extract VeloCloud Event Log to Splunk via REST API via Splunk Modular Input. 

The API call to VeloCloud Orchestrator (VCO) specifies an interval to minimize the performance impact to VCO of frequent API calls. It is recommended an interval of 120-600 seconds to poll VCO.

There is some overlap between API calls to VCO (interval x 2) to ensure no records are missed. We assume the record ID associated with each VCO event record is ascending and we save the last record ID written and only write records to Splunk which are greater than the saved record ID.

We mask and encrypt the VCO password and save to the Splunk Password DB. We encrypt the VCO session cookie and also save to the Splunk Password DB.

# Version
1.0.0

# Author
Dwayne Sinclair / djs 06/19 - 01/20 / VMware

Roger Huang 2020/11 / SST - 1.support opreator event 2.support Orchestrator 4.X

# With thanks to:
Ken Guo, Andrew Lohman, Kevin Fletcher

# Installation / Setup
Copy the vmware_sdwan_event folder to $SPLUNK_HOME/etc/apps and restart Splunk.

# Dependencies
-	Splunk Enterprise 8.1+
-	Python 3.7
-	VeloCloud Orchestrator enterprise username and password credentials
-	Enterprise user account must be “Superuser”, “Standard Admin”, or “Customer Support” role.

# New VeloCloud Orchestrator Endpoint Configuration

Required values are:

Name – The name given to this Modular Input. It is recommended to give it the name of the VeloCloud Orchestrator and Enterprise.

VCO URL – The https URL of the VeloCloud Orchestrator

Username – The VeloCloud Orchestrator username for a VCO enterprise user.

Account Type - Operator or Enterprise

Password – Matching password for the VeloCloud Orchestrator enterprise user.

Optional values are:

Cookie Refresh Time – Successful authentication to VeloCloud Orchestrator (VCO) using a userid and password returns a session cookie which is used for subsequent API calls. Setting this value between 0 and 24 hours is a maximum interval between VCO reauthenticating for a new session cookie. Setting this value to 0 forces the Modular Input to request a session cookie every time the event log is read. If something was to happen to VCO (DR activity etc), modifying the modular input to set this value to 0 then back to a high value is a simple way to regenerate and save a new session cookie. Default is 8 hours.

More Settings – Exposes additional configuration options. 

Interval – Polling interval in seconds between requests to the VeloCloud Orchestrator for event log data. Default is 300 seconds. Minimum is 120 seconds.

Source type, Host, and Index options are Splunk environment specific. Your Splunk administrator will recommend appropriate setting to use. 

# Issues
0120-1 - Low - The API call to VeloCloud Orchestrator incorporates a start and end interval. Start interval does not update if an API call to VeloCloud Orchestrator returns no data. A fix will be to update the start interval if no data is returned.

# Logging
Modular input event logging is to the splunkd.log file found at ../Splunk/var/log/splunk/splunkd.log. Filter on velocloud to find all events associated with this modular input.

# Sample Log
../velocloud_events.py" Cookie time read: 2020-01-01 22:44:52.337208 VCO--12

../velocloud_events.py" Cookie read from Password DB for: VCO--12 

../velocloud_events.py" No Cookie required for: VCO--12

../velocloud_events.py" Last Position read is: 1109532 for: VCO--12

../velocloud_events.py" Last Time Logged is: 2020-01-01T22:45:05.667827Z for: VCO--12

../velocloud_events.py" Request to VCO is: {'interval': {'end': '2020-01-01T23:33:35.169909Z', 'start': '2020-01-01T22:45:05.667827Z'}} for: VCO--12

../velocloud_events.py" 1 records returned from VCO Request for: VCO--12

../velocloud_events.py" Last Position out is: 1109553 for: VCO--12

../velocloud_events.py" Last Time out is: 2020-01-01T23:33:35.169909Z for: VCO--12

../velocloud_events.py" 1 VeloCloud events written to log for: VCO--12

../velocloud_events.py" Cookie time read: 2020-01-01 22:43:42.559030 VCO--47

../velocloud_events.py" Cookie read from Password DB for: VCO--47 

../velocloud_events.py" No Cookie required for: VCO--47

../velocloud_events.py" Last Position read is: 71510885 for: VCO--47

../velocloud_events.py" Last Time Logged is: 2020-01-01T22:44:58.507862Z for: VCO--47

../velocloud_events.py" Request to VCO is: {'interval': {'start': '2020-01-01T22:44:58.507862Z', 'end': '2020-01-
01T23:33:36.454618Z'}} for: VCO--47

../velocloud_events.py" 0 records returned from VCO Request for: VCO--47
