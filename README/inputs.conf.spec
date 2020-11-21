[vmware_sdwan_event://<name>]

* VCO URL – The https URL of the VeloCloud Orchestrator
root_url = <value>

* Username – The VeloCloud Orchestrator username for a VCO enterprise user.
username = <value>

* Accout Type - Default is Operator(True), Enterprise(False)
account_type = <value>

* Password – Matching password for the VeloCloud Orchestrator enterprise user.
password = <value>

* Cookie Refresh Time – Successful authentication to VeloCloud Orchestrator (VCO) using a userid and password returns a session cookie which is used for subsequent API calls. Setting this value between 0 and 24 hours is a maximum interval between VCO reauthenticating for a new session cookie. Setting this value to 0 forces the Modular Input to request a session cookie every time the event log is read. If something was to happen to VCO (DR activity etc), modifying the modular input to set this value to 0 then back to a high value is a simple way to regenerate and save a new session cookie. Default is 8 hours.
crefresh = <value>
