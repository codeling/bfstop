# com\_bfstop
## Brute Force Stop Joomla! Component

Main author: Bernhard Fröhler

This is the component part of the [Brute Force Stop Joomla! Extension package](https://extensions.joomla.org/extensions/extension/access-a-security/site-security/brute-force-stop/).

For detailed information, as well as instructions on how to download, install and configure Brute Force Stop, please browse to [the bfstop wiki](https://github.com/codeling/bfstop/wiki).

If you find any issues, please report them at [the bfstop issue tracker](https://github.com/codeling/bfstop/issues).

If you are interested in the source code, or want to contribute, please check [the bfstop source repository](https://github.com/codeling/com\_bfstop) at github.

For any further questions, don't hesitate to contact me under bfstop@bfroehler.info

## Security changes in this release

- The link in the "you were blocked" email now only asks for confirmation when
  opened; the unblock itself is a POST request, and only works from the IP
  address which was blocked (so mail scanners and link previews can't use it).
- The log view and the IP information view now escape everything they show.
- The unblock page answers with an error status if the link can't be used (400,
  403, 404 or 500; a GET request just asks for confirmation and stays a 200),
  unless the plugin's "Use HTTP Error" setting is off. Because the link contains
  a secret, the page is not cached, sends no Referer and asks search engines
  not to index it.
- New setting "Usernames Not Matching an Account" (default: hash), see the
  plugin's CHANGELOG.
- New setting "IPv6 Tracking Granularity" (default: /64).
- The "User Block Message" setting has a new value: the email with the unblock
  link is by default only sent if the user has logged in from the blocked IP
  address before, so it can't be used to flood somebody's inbox.
- Sending the test email needs the permission to change the settings, and the
  .htaccess and GeoIP database path settings are validated.
- Subnets with a prefix length like `1e1` or `0x8` are no longer accepted.
- The "Blocked IPs (database)" list now shows whether expired blocks are deleted
  automatically ("Prune old attempts" setting), and the log view explains that
  the log file is rotated at 5 MB.

## 2.0.0: Joomla 5/6 migration

Version 2.0.0 migrates the component to PSR-4 namespaced classes
(`Codeling\Component\Bfstop`) and drops support for Joomla 3/4. Notable change
for integrators: the frontend `router.php` was removed, since all of its
build/parse logic was already commented out and effectively a no-op; Joomla's
default component router is used instead, with no change in behaviour.

BFStop's configuration was also consolidated into this component's Settings
view (Components -> Brute Force Stop -> Settings). It used to be split
between here and the plugin's own Options tab in the Plugin Manager; the
plugin manifest no longer defines any configuration fields, so the
component's Settings view is now the single place to configure BFStop
(enabling/disabling the plugin itself still happens in the Plugin Manager,
as with any Joomla plugin).

This version also adds adaptive, risk-based allowance of failed login
attempts (issue #76): failed logins are now throttled per account across
all source IPs combined (not just per IP), and an optional per-attempt
risk score (known IP/username pairs, common usernames, missing
User-Agent, GeoIP country, reverse-DNS) adjusts delay and block
thresholds - see the plugin's CHANGELOG for the full list, and the
new "Account-level Throttle", "GeoIP Database", and "Adaptive Risk
Scoring" fieldsets in the Settings view. The "Information for IP
Address" view (issue #169) also works again, using the same local
GeoIP database instead of the discontinued freegeoip.net API it used
to depend on.

