# Performance comparison

Compares what the bfstop plugin costs a Joomla site in two versions - by
default the release 1.5.2 and the current checkout - against a site without
bfstop at all. Not part of CI: the numbers depend on the machine, so they are
only meaningful when both versions are measured on the same one, in one run.

## What is measured

All three sites run the same Joomla (default 5.4.8, the newest Joomla which
both versions support), PHP and database, each in its own database. The
plugins are installed from the release zip that their own `deploy.sh zip`
builds, with their default settings. The sites are served by PHP's built-in
web server (OPcache on), a request at a time.

- **Installed footprint**: size of the package and the installed files, lines
  of PHP, number and size of the (empty) database tables.
- **Overhead per request** (sequential requests, the three sites taking turns
  so that drifts of the machine hit all of them): server-side time, CPU time,
  peak memory, PHP files loaded, SQL queries run by Joomla - for each of:
  - `home`, `admin_login`, `login_page`: anonymous page views; bfstop checks
    the client address against allow- and blocklist
  - `login_fail`: a failed login (unknown user name, every time another
    client address); bfstop records it and checks if it has to block
  - `attack_fail`, `attack_block`, `attack_rejected`: one client address
    failing to log in over and over; the failed attempts, the one that gets
    the address blocked, and the attempts rejected afterwards (note that the
    default number of failed attempts before a block differs between the
    versions, so these requests are not equally frequent)
  - `home_blocked`: a page view from a blocked address, which bfstop answers
    itself
  
  Each is repeated with database tables of different sizes (`--sizes`): that
  many failed logins and a tenth of that many blocks, to show how the lookups
  scale (neither version indexes the address columns).
- **Throughput**: the same requests with several clients at the same time and
  several PHP workers (requests/second, latency percentiles).
- **Database growth**: bytes stored per failed login, including the tables
  only the current version has (user name statistics, known addresses).
- **Queries**: the SQL on bfstop's tables a single request sends (from
  MariaDB's general log), to explain differences in the numbers above.

Client address: requests come from `127.x.y.z` addresses, which the client
binds to (the whole range is the machine's loopback). So each failed login can
come from its own address, and `127.0.0.2` can be the blocked one. For this to
work the plugins use the connection's address, which both of them do by default.

## Requirements

- PHP 8.2+ with `curl`, `mysqli`, `pcntl`, `posix`, `zip`; `zip`, `unzip`,
  `curl` and `git` on the path, the `mysql` client
- a MariaDB 10.5+ server (the data is generated with its sequence engine; MySQL
  can't do that), reachable with an account which may create databases and
  switch on the general log (`SUPER`). **The databases `bfperf_none`,
  `bfperf_baseline` and `bfperf_current` are overwritten.** 1.5.2 has no
  PostgreSQL support, so the comparison needs MySQL/MariaDB.
- network access to download Joomla
- the tag of the old version in your checkout: `git fetch --tags`

## Running

    export DB_HOST=127.0.0.1 DB_USER=root DB_PASS=secret
    tests/performance/run.sh               # sets up the sites, then measures
    tests/performance/run.sh --quick       # a few minutes, rougher numbers

or in two steps, `tests/performance/setup-sites.sh` and `php
tests/performance/bench.php [options]`. The sites are kept in `$BENCH_DIR`
(default `/tmp/bfstop-perf`) and re-used by the next run; delete the
directory to start over. `setup-sites.sh` installs the plugin packages
again every time (building them from the refs as they are then), so changed code
is picked up.

Setup environment (`setup-sites.sh`): `JOOMLA_VERSION`, `BENCH_DIR`,
`DB_HOST`, `DB_USER`, `DB_PASS`, `BASELINE_REF` (default `1.5.2`),
`CURRENT_REF` (default `HEAD`) - any two refs of this repository can be
compared, as long as they run on the same Joomla.

`bench.php` options: `--requests` (per scenario, default 200), `--warmup`,
`--sizes` (default `0,100000`; `1000000` is slow but instructive),
`--scenarios` (comma separated: `home`, `home_blocked`, `admin_login`,
`login_fail`, `attack`), `--throughput` (requests per round, 0 = skip),
`--concurrency`, `--workers`, `--rounds`, `--growth`, `--no-trace`, `--quick`.

The report is written to `$BENCH_DIR/results/<time>/report.md` (with
`results.json` and the raw per-request metrics next to it) and printed.

## Reading the numbers

- Queries, PHP files, classes and memory don't vary between runs; times do. On
  a shared machine, differences of a millisecond or two between versions are
  noise. Run it again, and don't compare reports from different machines.
- Wall time of the failed logins is dominated by Joomla itself (password
  checking, session handling); look at the *difference* to the site without
  bfstop.
- Client and server share the machine in the throughput runs, so absolute
  requests/second say little, only the relation between the three sites.
- Both versions are used with their default settings, which are not the same:
  e.g. what the current version does with a failed login depends on its risk
  score. Requests carry a browser's `User-Agent`, as without one the current
  version scores the request as suspicious and, by default, delays the answer
  to a failed login by several seconds (`riskDelaySecondsPerPoint`) - a
  deliberate cost to a bot, but it would swamp everything else here. Likewise
  every failed login uses another user name: repeating one would trigger the
  account-level throttle, a 5 second delay after 20 failures within an hour.
