# Tests

- `Unit/`: tests needing nothing but PHP and [PHPUnit](https://phpunit.de) 11.
- `Integration/`: tests against a real Joomla site with bfstop installed. They
  run every database query of the library and of the component on the site's
  database, and let the plugin react
  to Joomla events as on a live site (failed logins, requests from blocked
  addresses). Skipped if `JOOMLA_ROOT` is not set.

Two integration tests, `UnblockPageHttpTest` and `ParallelLoginHttpTest`, make
real HTTP requests to PHP's built-in web server running the Joomla site (the
status and headers of a response can't be seen from a CLI process, and logins
sent at the same time need a server with several workers; the latter test
needs the curl extension): they test the plugin and component as *installed*
in the site, so after changing them, copy them there first
(`plugin/deploy.sh <joomla dir>` and `component/deploy.sh <joomla dir>`, or run
`tests/ci/install-joomla.sh` again).

The classes under test are always loaded from this checkout (`library/`,
`plugin/`, `component/`), not from the copies installed into the Joomla site, so
the site only needs to be set up again when the database schema changes.

- `Upgrade/`: the update from the previous release, run by
  `ci/upgrade-test.sh` only (skipped otherwise): a Joomla site with the
  release named in `ci/previous-release.sha256` (downloaded from the GitHub
  release and checked against that SHA-256), given settings and data in the
  form that version kept them (`Upgrade/fixtures/seed.php`), is updated with
  the package (`$BFSTOP_PACKAGE`). The tests check the versions and schema,
  the migrated settings, the converted tables and addresses, that blocks
  still work, that an update which stopped halfway can be run again, and that
  the package refuses a Joomla version it doesn't support. After a release,
  put the new one into `ci/previous-release.sha256` (the file says how).
- `lint/`: checks of the versions (`check-versions.php`, see
  `package/README.md`), of the language files (`check-language.php`), of the
  release zips built by `deploy.sh zip` (`check-zip.php`) and of the GitHub
  Actions workflows (`check-workflows.php`: every action pinned to a commit
  SHA, with its release in a comment; Dependabot proposes the updates).
- `ci/apache-htaccess.sh`: the block section `HtaccessHelper` writes, checked
  against a real Apache 2.4 (CI job ".htaccess blocks on Apache"): it turns
  away the blocked addresses and doesn't open up what the directory's other
  access controls keep out.
- `Integration/MaintenanceTest.php` is about the daily maintenance: when a request
  has to do it (it didn't run for two days), what it does, and that Joomla's
  Task Scheduler runs it through the task plugin (the scheduler's own
  command line is called, on the installed site).
- `Integration/RequestClassifierTest.php` compares what the plugin's
  `RequestClassifier` says a request does (a login, the unblock page, the
  password recovery) with what the Joomla site under test runs for it
  (`fixtures/classify.php`: Joomla's own `findOption()`, component dispatchers
  and `BaseController::execute()`, with a controller that records the task
  instead of running it). The classifier rebuilds Joomla internals, so this is
  what tells whether a Joomla version still handles requests the way it
  expects; CI runs it on every Joomla version of the matrix.
- `Integration/SetupTest.php` is about the setup assistant: its steps,
  saved through the settings model with the fixes of stored values which
  would keep the settings from being saved (settings of 1.5.2), the dry run
  of the proxy settings, the activation of the plugin, the banners, the
  quick icon, the pages rendered for each kind of request, the optional
  steps (the clean-up after the proxy fix, the .htaccess section of 1.x,
  the steps of settings, hashing the usernames of 1.x, the scheduler), and
  the console commands (called on the installed site). `InstallerScriptTest` has the
  activation model of the installation and the update (the plugin
  disabled by an update behind a proxy, not where the proxy is set up), and
  checks that the update tells the proxy scenarios apart and matches
  trusted proxies as the library does (`ProxyDetector`, whose unit test has
  the table of scenarios, and `IpHelper`). `CloudflareRangesTest` fetches
  Cloudflare's ranges from PHP's built-in web server (with
  `fixtures/cloudflare.php`): no redirect is followed, no long answer read.
- `Integration/QueryCountTest.php` keeps the number of queries a page view, the
  request of a blocked address and a failed login send within limits (the
  scripts of `Integration/fixtures` print the queries when called with
  `--count-queries`). A change which needs another query raises the limit of
  its kind, and the message lists the queries.
- `phpstan/` and `ci/phpstan.sh`: static analysis, see "Static analysis" below.
- `performance/`: not a test, a comparison of what two versions of the plugin
  (by default 1.5.2 and the checkout) cost a Joomla site, see its README. Not
  run by phpunit or CI.

GitHub Actions runs everything on each push and pull request, on Joomla 5 and
6 with MySQL, MariaDB and PostgreSQL, see `.github/workflows/ci.yml`. The
sites there have bfstop installed from the package which the "Package" job
built with `package/build.sh` - the zip users would get, kept as an artifact
of the run - whose setup `ci/install-joomla.sh` completes with
`bfstop:setup --no-proxy` (the system plugin installs disabled, see the setup
assistant), and the "Update from the previous release" jobs run
`ci/upgrade-test.sh` with it, on the Joomla 5 sites with MySQL/MariaDB.

### Static analysis

[phpstan](https://phpstan.org) at level 5 analyses `library/src`, `plugin/src`
and `component/*/src` (not the vendored GeoIP reader, `library/src/Helper/Geo`;
not the layouts in `component/*/tmpl`); the configuration is `phpstan.neon`, CI
runs it in the job "Static analysis (phpstan)". Joomla has no stubs package, so
phpstan scans the `libraries/` directory of an unpacked Joomla full package
for the types of Joomla's classes: `tests/ci/phpstan.sh` downloads (and
verifies, like the integration tests do) the newest version of
`tests/ci/matrix.json`, or uses the Joomla in `JOOMLA_ROOT`.

    composer install
    tests/ci/phpstan.sh

The findings that were there when phpstan was introduced are listed in
`phpstan-baseline.neon`; the job fails for any other. Fix a finding by
removing its entry from the baseline together with the code change (phpstan
reports baseline entries that no longer match). Don't add to the baseline for
new code; if it has to be regenerated (after raising the Joomla version, for
example):
`tests/ci/phpstan.sh --generate-baseline phpstan-baseline.neon`, and look at
what changed.

### Joomla versions of the CI matrix

The matrix runs one Joomla version per major version. It is `tests/ci/matrix.json`
(which `ci.yml` reads in a first job), each version with its SHA-256 in
`tests/ci/joomla-checksums.sha256`; raise a version in both files, the lint
checks that they agree. Dependabot can't follow those, so
`.github/workflows/joomla-versions.yml` looks at the releases of
`joomla/joomla-cms` every week (and on demand: Actions, "Joomla versions", Run
workflow - not "Re-run" of an old run, which uses the workflow file of that
run):

- a newer **patch release** of a version in the matrix gets a pull request
  (branch `joomla-versions`) that raises the matrix and adds the checksum. The
  hash is the one of the downloaded package, which must equal the digest GitHub
  lists for the release asset. Compare MD5/SHA1 with downloads.joomla.org
  before merging; that is the check against Joomla's own page. A push with the
  workflow's token doesn't start `pull_request` workflows, so the job starts
  `ci.yml` on the branch itself.
- a release of a **newer minor/major line** (e.g. 6.2 when the matrix has 6.1)
  only gets an issue: whether to support it is a decision.

The database images of the matrix are pinned by their digest (`"digest"`, the
same for every entry of an image; the lint checks it), as the actions are:
what runs in CI is the image that was looked at. Neither Dependabot nor the
weekly job update them; when raising one, take the digest from Docker Hub (or
`docker buildx imagetools inspect <image>`).

For the pull requests, the repository setting "Allow GitHub Actions to create
and approve pull requests" has to be on. The planning and the edits are
`tests/ci/joomla-updates.php` (unit-tested in `tests/Unit/JoomlaUpdatesTest.php`).
Entries of versions which are no longer in the matrix are harmless (the lint
only notes them) and can be removed.

## Running locally

Unit tests only:

    phpunit -c tests/phpunit.xml.dist --testsuite unit

For the integration tests, create an empty database, then let
`tests/ci/install-joomla.sh` set up a Joomla site with bfstop in it (it
downloads Joomla, installs it, then builds the package from this checkout
with `package/build.sh` and installs it - or the package
zip given in `BFSTOP_PACKAGE`). The download is only unpacked if its SHA-256 is the one in
`tests/ci/joomla-checksums.sha256`; for a version that isn't listed, add it
there (the file says how to check it) or pass the hash as `JOOMLA_SHA256`. To
keep the downloaded packages for the next run, point `DOWNLOAD_CACHE` at a
directory (CI does so); a package found there is used again only if its SHA-256
still matches. **Everything in that database will be overwritten.** For example,
with PostgreSQL:

    export JOOMLA_VERSION=5.4.10 JOOMLA_ROOT=/tmp/bfstop-joomla \
        DB_TYPE=pgsql DB_HOST=127.0.0.1 DB_USER=postgres DB_PASS=secret DB_NAME=bfstop_test
    tests/ci/install-joomla.sh
    phpunit -c tests/phpunit.xml.dist

`DB_TYPE` is `mysqli` for MySQL/MariaDB. The tests empty the bfstop tables
and change the plugin's settings (restoring them afterwards), so don't point
`JOOMLA_ROOT` at a site you care about.

The update test needs an empty MySQL/MariaDB database and a directory without
a Joomla site in it, and the package to update to:

    package/build.sh
    export JOOMLA_VERSION=5.4.10 JOOMLA_ROOT=/tmp/bfstop-upgrade \
        BFSTOP_PACKAGE=build/pkg_bfstop-2.0.0.zip \
        DB_TYPE=mysqli DB_HOST=127.0.0.1 DB_USER=root DB_PASS=secret DB_NAME=bfstop_upgrade
    tests/ci/upgrade-test.sh
