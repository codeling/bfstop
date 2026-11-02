# Tests

- `Unit/`: tests needing nothing but PHP and [PHPUnit](https://phpunit.de) 11
  (the component's IP range tests only run if `COM_BFSTOP_ROOT` is set).
- `Integration/`: tests against a real Joomla site with bfstop installed. They
  run every database query of the plugin (and of the component, if
  `COM_BFSTOP_ROOT` is set) on the site's database, and let the plugin react
  to Joomla events as on a live site (failed logins, requests from blocked
  addresses). Skipped if `JOOMLA_ROOT` is not set.

One integration test, `UnblockPageHttpTest`, makes real HTTP requests to PHP's
built-in web server running the Joomla site (the status and headers of a
response can't be seen from a CLI process): it tests the plugin and component
as *installed* in the site, so after changing them, copy them there first
(`./deploy.sh <joomla dir>` in each checkout, or run
`tests/ci/install-joomla.sh` again).

The classes under test are always loaded from this checkout (and the
component checkout), not from the copies installed into the Joomla site, so
the site only needs to be set up again when the database schema changes.

- `lint/`: checks of the language files (`check-language.php`), of the
  release zip built by `deploy.sh zip` (`check-zip.php`) and of the GitHub
  Actions workflows (`check-workflows.php`: every action pinned to a commit
  SHA, with its release in a comment; Dependabot proposes the updates); the
  scripts are kept identical in the com_bfstop repository.
- `performance/`: not a test, a comparison of what two versions of the plugin
  (by default 1.5.2 and the checkout) cost a Joomla site, see its README. Not
  run by phpunit or CI.

GitHub Actions runs everything on each push and pull request, on Joomla 5 and
6 with MySQL, MariaDB and PostgreSQL, see `.github/workflows/ci.yml`.

Plugin and component are tested together, and each repository's workflow checks
out the other one: the branch of the same name if that exists **and has commits
`main` doesn't** (for a change spanning both repositories), else `main`. A
branch that was merged and not deleted is therefore ignored, not tested against.

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

For the pull requests, the repository setting "Allow GitHub Actions to create
and approve pull requests" has to be on. The planning and the edits are
`tests/ci/joomla-updates.php` (unit-tested in `tests/Unit/JoomlaUpdatesTest.php`).
The com_bfstop workflow does not have a matrix of its own: it reads
`tests/ci/matrix.json` of the plugin checkout it tests with (the same branch
choice as above) and installs through the same checksum file, so both
repositories always run the same combinations. Entries of versions which are
no longer in the matrix are harmless (the lint only notes them) and can be
removed.

## Running locally

Unit tests only:

    phpunit -c tests/phpunit.xml.dist --testsuite unit

For the integration tests, create an empty database, then let
`tests/ci/install-joomla.sh` set up a Joomla site with bfstop in it (it
downloads Joomla, installs it, then installs plugin and component from the
checkouts). The download is only unpacked if its SHA-256 is the one in
`tests/ci/joomla-checksums.sha256`; for a version that isn't listed, add it
there (the file says how to check it) or pass the hash as `JOOMLA_SHA256`. **Everything in that database will be overwritten.** For example,
with PostgreSQL:

    export JOOMLA_VERSION=5.4.8 JOOMLA_ROOT=/tmp/bfstop-joomla \
        COM_BFSTOP_ROOT=/path/to/com_bfstop \
        DB_TYPE=pgsql DB_HOST=127.0.0.1 DB_USER=postgres DB_PASS=secret DB_NAME=bfstop_test
    tests/ci/install-joomla.sh
    phpunit -c tests/phpunit.xml.dist

`DB_TYPE` is `mysqli` for MySQL/MariaDB. The tests empty the bfstop tables
and change the plugin's settings (restoring them afterwards), so don't point
`JOOMLA_ROOT` at a site you care about.
