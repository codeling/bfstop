# Tests

- `Unit/`: tests needing nothing but PHP and [PHPUnit](https://phpunit.de) 11.
- `Integration/`: tests against a real Joomla site with bfstop installed. They
  run every database query of the plugin (and of the component, if
  `COM_BFSTOP_ROOT` is set) on the site's database, and let the plugin react
  to Joomla events as on a live site (failed logins, requests from blocked
  addresses). Skipped if `JOOMLA_ROOT` is not set.

The classes under test are always loaded from this checkout (and the
component checkout), not from the copies installed into the Joomla site, so
the site only needs to be set up again when the database schema changes.

GitHub Actions runs everything on each push and pull request, on Joomla 5 and
6 with MySQL, MariaDB and PostgreSQL, see `.github/workflows/ci.yml`.

## Running locally

Unit tests only:

    phpunit -c tests/phpunit.xml.dist --testsuite unit

For the integration tests, create an empty database, then let
`tests/ci/install-joomla.sh` set up a Joomla site with bfstop in it (it
downloads Joomla, installs it, then installs plugin and component from the
checkouts). **Everything in that database will be overwritten.** For example,
with PostgreSQL:

    export JOOMLA_VERSION=5.4.8 JOOMLA_ROOT=/tmp/bfstop-joomla \
        COM_BFSTOP_ROOT=/path/to/com_bfstop \
        DB_TYPE=pgsql DB_HOST=127.0.0.1 DB_USER=postgres DB_PASS=secret DB_NAME=bfstop_test
    tests/ci/install-joomla.sh
    phpunit -c tests/phpunit.xml.dist

`DB_TYPE` is `mysqli` for MySQL/MariaDB. The tests empty the bfstop tables
and change the plugin's settings (restoring them afterwards), so don't point
`JOOMLA_ROOT` at a site you care about.
