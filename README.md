# Brute Force Stop: Joomla! system plugin

Brute Force Stop (BFStop) protects the login of a Joomla! site against
brute-force attacks. It records failed logins, slows down and blocks the IP
addresses (and throttles the accounts) they come from, notifies you about
failed logins and blocks, and lets users who blocked themselves unblock their
address through a link sent by email.

This repository contains the **plugin** (`plg_system_bfstop`), which does the
work on every request: it watches the logins and rejects requests from
blocked addresses. The plugin has no settings of its own. These, and the
lists of blocked addresses, failed logins and allowed addresses, are in the
**component** ([codeling/com_bfstop](https://github.com/codeling/com_bfstop)),
which also provides the unblock page. Plugin and component only work together.

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
- Changes: [CHANGELOG](CHANGELOG) (for plugin, component and package)
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

- Package and releases: the package is built from this repository and
  com_bfstop by `package/build.sh`; how versions and releases work is
  described in [package/README.md](package/README.md).
- Tests: [tests/README.md](tests/README.md). CI tests plugin and component
  together; for a change spanning both repositories, use the same branch name
  in both.
- Contributions are welcome, as pull requests to this repository or to
  com_bfstop.

### GeoIP reader

The reader is third-party code: keep it up to date!

The optional GeoIP features (country risk score, "Information for IP Address")
use a copy of the MaxMind DB reader (maxmind-db/reader, Apache-2.0), shipped in
`src/Helper/Geo`, because a Joomla! extension cannot rely on composer at install
time. It parses a database file with untrusted-format binary data, so it has to
be updated whenever MaxMind publishes a new release - releases of this plugin
should never ship an outdated copy.

- **Which version is shipped:** `composer.lock` (package maxmind-db/reader);
  the header of `src/Helper/Geo/Reader.php` names it too.
- **How it is kept current:** Dependabot and a weekly GitHub Actions job
  (`.github/workflows/dependencies.yml`) report new releases and security
  advisories; CI fails if `src/Helper/Geo` is not exactly the locked version.
- **How to update:** `composer update maxmind-db/reader && composer vendor-geoip`,
  review the diff, run the tests, release plugin and component.
- The GeoLite2/GeoIP2 *database* (`.mmdb`) is separate: you download it and
  configure its path in the component's settings. MaxMind publishes new
  versions of GeoLite2 twice a week (Tuesdays and Fridays), and the
  addresses of the internet move around, so an old file gets less and less
  accurate - it only feeds the risk score and the address information, it is
  not a security boundary. Update it regularly (geoipupdate can do that from
  cron), and check the licence terms of the database you use: they may
  require you to keep it current.

## License

GNU General Public License, version 3, see [LICENSE.txt](LICENSE.txt).
