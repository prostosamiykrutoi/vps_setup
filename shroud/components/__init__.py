"""Proxy-stack components. Each wraps one container/protocol and knows how to:

* generate/load its secrets (into state refs + the credentials file),
* render its config file(s) into the runtime dir,
* contribute a docker-compose service fragment,
* emit client connection link(s).

Components are pinned to images/params from the profile (volatile layer); none of
this code hardcodes a version.
"""
