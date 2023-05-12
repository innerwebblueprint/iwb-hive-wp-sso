# iwb-hive-wp-sso

IWB Hive WP SSO (Single Sign On) is a WordPress plugin to faciliate logging in to a self hosted WordPress site using a Hive account. Hive as in https://hive.io/

A WordPress user account will be created for any Hive authenticated user that does not already have one. If a WordPress account already exists with that username, the user will be logged into that account. Hive usernames are globally unique, but do take note before using this plugin that if you already have WordPress accounts that match a Hive username, this plugin will allow that authenticated user to login to that account.

Currently this plugin is dependent on a specific python library, beempy, to verify the cryptographic signature. I have this library built into the IWB Website Factory Docker Image, so if you are using that image this should work fine.

If not, you will likely need to install the python bemmpy library to use this plugin. It is highly unlikely that any standard WordPress hosting will have this library available. This plugin will currently not work without it. In a future version (as soon as I figure out how) I plan to support signature verification natively in php so this plugin can be used across a broader spectrum without the python dependency.

You can read more about the plugin here:

https://www.innerwebblueprint.com/category/roadmap/iwb-wordpress-plugins/
