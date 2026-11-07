# Brute Force Stop: Joomla! administration component

Brute Force Stop (BFStop) protects the login of a Joomla! site against
brute-force attacks. It records failed logins, slows down and blocks the IP
addresses (and throttles the accounts) they come from, notifies you about
failed logins and blocks, and lets users who blocked themselves unblock their
address through a link sent by email.

This repository contains the **component** (`com_bfstop`): BFStop's settings,
the lists of blocked addresses, failed logins and allowed addresses, the log,
username statistics and IP address information in the administrator backend,
and the unblock page in the frontend. The work on every request, watching the
logins and rejecting requests from blocked addresses, is done by the
**plugin** ([codeling/bfstop](https://github.com/codeling/bfstop)). Plugin and
component only work together.

## Usage

- Install the **package** `pkg_bfstop-<version>.zip` from the
  [releases](https://github.com/codeling/bfstop/releases). It contains the
  plugin and the component and installs both. Don't install them separately:
  they are released together, and need to have the same version.
- Requirements: Joomla! 5 or 6, PHP 8.1 or newer, and MySQL, MariaDB or
  PostgreSQL. Sites still on Joomla! 4 stay with BFStop 1.5.
- The plugin is enabled when it is installed. Configure BFStop under
  *Components → Brute Force Stop → Settings*.
- Joomla! offers updates through its update manager.

## Resources

- Documentation: [the bfstop wiki](https://github.com/codeling/bfstop/wiki)
- Downloads: [GitHub releases](https://github.com/codeling/bfstop/releases),
  [Joomla! Extensions Directory](https://extensions.joomla.org/extensions/extension/access-a-security/site-security/brute-force-stop/)
- Changes: [CHANGELOG](https://github.com/codeling/bfstop/blob/main/CHANGELOG)
  (for plugin, component and package)
- Bug tracker (for plugin and component):
  [codeling/bfstop issues](https://github.com/codeling/bfstop/issues)
- Security issues: please don't report them in the bug tracker, see
  [SECURITY.md](SECURITY.md)
- Update server: `https://bfstop.bfroehler.info/update.xml`
- Source: [codeling/bfstop](https://github.com/codeling/bfstop) (plugin and
  package), [codeling/com_bfstop](https://github.com/codeling/com_bfstop)
  (component)
- Contact: info@bfstop.de

## Development

- Package and releases: the package is built from the plugin repository and
  this one by `package/build.sh` of codeling/bfstop; how versions and releases
  work is described in its
  [package/README.md](https://github.com/codeling/bfstop/blob/main/package/README.md).
- Tests: the tests of plugin and component are in the plugin repository, see
  its [tests/README.md](https://github.com/codeling/bfstop/blob/main/tests/README.md).
  CI tests plugin and component together; for a change spanning both
  repositories, use the same branch name in both.
- Contributions are welcome, as pull requests to this repository or to
  codeling/bfstop.

## License

GNU General Public License, version 3, see [LICENSE.txt](LICENSE.txt).
