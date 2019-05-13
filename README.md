
Simple proxy to authenticate with the openidconnect protocol using a ldap federation implemented in PHP.

The idea is that it is written in as few lines of code as possible and with the least amount of dependencies for easy installation in LAMP environments.

This is the initial version with which I am learning about protocols. It works in the simplest case that is the unencrypted token request.

In the configuration file you can see how to configure the ldap server.

Currently for testing use the following server: https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/