# Brute Force Stop for Joomla!

Brute Force Stop (BFStop) protects the login of a Joomla! site against
brute-force attacks. It records failed logins, blocks the IP addresses they
come from (sooner when an account is attacked from many addresses), notifies
you about failed logins and blocks, and lets users who blocked themselves
unblock their address through a link sent by email.

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
- `quickicon/`: the **quick icon plugin** (`plg_quickicon_bfstop`), a tile
  on the Home Dashboard which says whether BFStop is active and whether the
  proxy settings still fit how the site is reached.
- `console/`: the **console plugin** (`plg_console_bfstop`), the commands
  `bfstop:status`, `bfstop:setup` and `bfstop:unblock` of Joomla's command
  line (`php cli/joomla.php`).
- `package/`: the package (`pkg_bfstop`) which contains them, and how it is
  built and released.

Plugins and component only work together; none of them uses the classes
of another, only those of the library - except the console plugin, whose
`bfstop:setup` saves the settings through the setup assistant's model of
the component (booted through Joomla), so that the same checks apply.

## Usage

- Install the **package** `pkg_bfstop-<version>.zip` from the
  [releases](https://github.com/codeling/bfstop/releases). It contains the
  plugins, the component and the library and installs them all. Don't
  install them separately: they are released together, and need to have the
  same version.
- Requirements: Joomla! 5.4 or 6, PHP 8.2 or newer, and MySQL, MariaDB or
  PostgreSQL. Sites still on Joomla! 4 stay with BFStop 1.5.
- After installing (and after the update from 1.5), run the **setup
  assistant** in *Components → Brute Force Stop → Setup Assistant*: it checks
  how visitors reach the site (directly, or through a proxy, load balancer or
  CDN, which BFStop has to be told about, or it would block the proxy's
  address - and with it everybody) and whether the blocking mode fits the web
  server, and then **activates the plugin**, which installs disabled. Until
  then, BFStop doesn't protect anything; the Home Dashboard and the BFStop
  pages say so. An update through the browser whose request came through a
  proxy disables the plugin until the assistant is done; an update from the
  command line does where Joomla's "Behind Load Balancer" is on.
- On the command line: `php cli/joomla.php bfstop:status` shows where the
  setup stands, `php cli/joomla.php bfstop:setup --no-proxy` (or
  `--trusted=<proxies> --header=<header>`, e.g.
  `--trusted=10.0.0.5 --header=X-Forwarded-For`) completes it and activates
  protection, and `php cli/joomla.php bfstop:unblock <address>` lifts the
  blocks of an address, with its `.htaccess` and nginx entries - for an
  administrator who locked everybody out.
- Where the command line can't be used, the plugin can be enabled in the
  Plugin Manager (*System → Plugins*, "System - Brute Force Stop"), and the
  blocks of an address lifted in the database:
  `INSERT INTO <prefix>bfstop_unblock (block_id, source, crdate) SELECT id, 0, CURRENT_TIMESTAMP FROM <prefix>bfstop_bannedip WHERE ipaddress = '<address>' AND id NOT IN (SELECT block_id FROM <prefix>bfstop_unblock);`
  (with blocking through `.htaccess`, take the address out of the file's
  `BFStop Blocks` section too). The banners and the quick icon keep saying
  that the setup isn't complete until the assistant has run.
- Configure everything else under *Components → Brute Force Stop →
  Settings*. Keep the proxy settings up to date: whenever the hosting
  changes (a new proxy or CDN, load balancer nodes added or replaced, a move
  to another host), run the proxy check of the assistant again.
- Joomla! offers updates through its update manager.

### Rate limiting

Blocking is what protects the login: an address (an IPv6 client: its
network) gets only so many failed logins, fewer if its attempts look risky
or the account it tries is attacked from many addresses at once. BFStop
answers every failed login at once and doesn't slow clients down: since
2.0.0, there are no delay settings any more. A response held back by PHP
holds a PHP worker for as long, so an attacker sending many attempts in
parallel, from many addresses, could run the server out of workers, while a
delay hardly slows down a client which doesn't wait for one answer before
sending the next attempt. Holding many connections open cheaply is something
only the web server or a proxy in front of it can do: to slow down or limit
requests to the login, use e.g. nginx's
[`limit_req`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html),
Apache's `mod_evasive` or `mod_qos`, or fail2ban. The wiki explains
[why the delays were removed](https://github.com/codeling/bfstop/wiki/Why-No-Delay-Options-in-2.0)
and has examples.

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
