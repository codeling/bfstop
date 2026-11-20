# Brute Force Stop for Joomla!

Brute Force Stop (BFStop) protects the login of a Joomla! site against
brute-force attacks. It records failed logins, slows down and blocks the IP
addresses (and throttles the accounts) they come from, notifies you about
failed logins and blocks, and lets users who blocked themselves unblock their
address through a link sent by email.

This repository contains all of BFStop, which is released as one package:

- `library/`: the **library** (`lib_bfstop`, namespace
  `Codeling\Library\Bfstop`) which the others use: addresses and networks,
  when and how a client is blocked (the block policy), the database tables
  (one repository class each), the `.htaccess` file, the mails, the log and
  the daily maintenance.
- `plugin/`: the **system plugin** (`plg_system_bfstop`), which does the work
  on every request, by the library: it watches the logins and rejects
  requests from blocked addresses. It has no settings of its own: they are
  the component's.
- `component/`: the **component** (`com_bfstop`): the settings, the lists of
  blocked addresses, failed logins and allowed addresses, the log, username
  statistics and IP address information in the administrator backend, and the
  unblock page in the frontend. It used to be the repository
  [codeling/com_bfstop](https://github.com/codeling/com_bfstop), whose history
  is part of this one now.
- `task/`: the **task plugin** (`plg_task_bfstop`), which runs the daily
  maintenance as a task of Joomla's Task Scheduler.
- `package/`: the package (`pkg_bfstop`) which contains them, and how it is
  built and released.

Plugins and component only work together; none of them uses the classes
of another, only those of the library.

## Usage

- Install the **package** `pkg_bfstop-<version>.zip` from the
  [releases](https://github.com/codeling/bfstop/releases). It contains the
  plugin and the component and installs both. Don't install them separately:
  they are released together, and need to have the same version.
- Requirements: Joomla! 5.4 or 6, PHP 8.1 or newer, and MySQL, MariaDB or
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
- Update server: `https://bfstop.de/update.xml`
- Source: [codeling/bfstop](https://github.com/codeling/bfstop) (plugins,
  component and package)
- Contact: info@bfstop.de

## Development

- Package and releases: the package is built by `package/build.sh`; how
  versions and releases work is described in
  [package/README.md](package/README.md).
- Tests: [tests/README.md](tests/README.md), for plugins and component.
- `update.xml` (at the top) is an empty file for the sites which still have a
  version of the plugin before 1.1.1, whose update server it was; the update
  server of the package is generated from the GitHub releases
  (`package/update-server.php`, deployed with the website in `site/` to
  `https://bfstop.de` by `.github/workflows/pages.yml`, see
  [package/README.md](package/README.md)).
- Static analysis: phpstan, see "Static analysis" in
  [tests/README.md](tests/README.md).
- Coding style: that of Joomla!, [PSR-12](https://www.php-fig.org/psr/psr-12/)
  (4 spaces, `if (...) {` on one line; the braces of classes and methods on
  their own line). New files follow it. The existing code still has tabs and
  braces on their own line everywhere, and is converted separately, not
  along with unrelated changes.
- Contributions are welcome, as pull requests to this repository.

### GeoIP reader

The reader is third-party code: keep it up to date!

The optional GeoIP features (country risk score, "Information for IP Address")
use a copy of the MaxMind DB reader (maxmind-db/reader, Apache-2.0), shipped in
`library/src/Helper/Geo`, because a Joomla! extension cannot rely on composer at install
time. It parses a database file with untrusted-format binary data, so it has to
be updated whenever MaxMind publishes a new release - releases of this plugin
should never ship an outdated copy.

- **Which version is shipped:** `composer.lock` (package maxmind-db/reader);
  the header of `library/src/Helper/Geo/Reader.php` names it too.
- **How it is kept current:** Dependabot and a weekly GitHub Actions job
  (`.github/workflows/dependencies.yml`) report new releases and security
  advisories; CI fails if `library/src/Helper/Geo` is not exactly the locked version.
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
