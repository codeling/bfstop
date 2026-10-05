# Security Policy

## Supported versions

Security fixes are made for the latest release of the BFStop plugin
(`plg_system_bfstop`) and the BFStop component (`com_bfstop`). The two are
released together and need to be on the same major and minor version, so
please update both.

## Reporting a vulnerability

Please report suspected vulnerabilities by email to **security@bfstop.de**
rather than in a public issue or pull request, so that a fix can be
available before details are public.

It helps to include:

- the affected version(s) of plugin and component, and the Joomla! and PHP
  versions,
- the relevant settings (blocking mode, proxy settings, ...),
- steps to reproduce, or a proof of concept, and what an attacker gains.

## What is and isn't in scope

BFStop sits in front of the login of a Joomla! site and decides which
requests to reject, so these are the kind of reports which are most useful:

- ways around a block or the failed-login counting (for example by faking
  the client address, or by reusing an unblock link),
- ways to get someone else blocked, or to make the plugin tie up the server,
- ways to read or change data (settings, blocks, logged usernames) without
  the necessary permissions, and cross-site scripting in the backend views.

Settings are changed by users with the `core.admin` permission for
`com_bfstop`. They can, among other things, choose the directory in which the
plugin writes its `.htaccess` file, so grant that permission only to people
you trust with the web server's configuration for your site.
