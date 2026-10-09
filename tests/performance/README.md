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

## Results

One run of `tests/performance/run.sh` with the default options, on a 4 CPU
container (shared by client, web server and database), on 2026-10-07:

| | |
| --- | --- |
| compared | tag `1.5.2` (`5dfb9cc0a7d0034afdcad37aa2a400d8adc0c2dd`) and `main` at `f85336be01c6c8c796f1de26d196dcd313d45ce7` (plugin version 2.0.0) |
| software | Joomla 5.4.8, PHP 8.3.6 (OPcache on), MariaDB 10.11.14 |
| load | 200 requests per scenario after 20 warm-up requests; tables with 0 and 100,000 failed logins (and a tenth of that many blocks); throughput with 8 clients and 4 PHP workers, median of 3 rounds of 400 requests |

Overhead is the median of the plugin's site minus the median of the same
request on a site without bfstop; "1.5.2 / current" in each cell. Times
differing by a millisecond or two are noise, the other columns don't vary.

| | 1.5.2 | current |
| --- | ---: | ---: |
| **Installed** | | |
| release zip | 85 KiB | 131 KiB |
| files / PHP lines | 59 / 1,550 | 73 / 4,488 |
| database tables | 5 | 8 |
| **Page view** (front page, login form, administrator login) | | |
| extra SQL queries | +5 | +3 |
| extra PHP files | +7 | +6 |
| extra peak memory | +10 to +35 KiB | +10 to +34 KiB |
| extra time, empty tables | +0.9 to +2.4 ms | +1.1 to +1.3 ms |
| extra time, 100,000 failed logins | +8.0 to +9.6 ms | +8.5 to +10.0 ms |
| **Failed login** | | |
| extra SQL queries | +12 | +13 |
| extra PHP files | +7 | +9 |
| extra peak memory | +64 KiB | +48 KiB |
| extra time, empty tables | +6.3 ms | +7.1 ms |
| extra time, 100,000 failed logins | +57.7 ms | +66.9 ms |
| stored per failed login | 74 bytes | 352 bytes |
| **Blocked client** (answered by bfstop, a normal page takes 29.5 ms) | | |
| time, empty tables | 13.9 ms | 15.1 ms |
| time, 100,000 failed logins | 18.6 ms | 20.8 ms |
| **Throughput** (requests/s; without bfstop in brackets) | | |
| front page, empty tables | 153.5 (170.9) | 157.7 |
| front page, 100,000 failed logins | 131.0 (167.5) | 126.5 |
| failed login, empty tables | 45.5 (48.6) | 45.0 |
| failed login, 100,000 failed logins | 30.4 (49.5) | 29.4 |
| blocked client, empty tables | 314.4 | 315.6 |
| blocked client, 100,000 failed logins | 241.8 | 205.0 |

What stands out:

- With small tables neither version costs much: a few queries per page view,
  and no measurable difference in time between them.
- The cost of both grows with the size of the failed login and block tables
  (the lookups scan them): with 100,000 failed logins a failed login takes
  about 60 ms more than without bfstop, and the throughput of failed logins
  drops by 40%.
- The current version stores about five times as much per failed login (an
  index on the failed logins, and the user name statistics table).
- The current version needs 2 queries instead of 4 to check a page view, but
  also counts each request of a blocked client (an `UPDATE`); with big tables
  it answers blocked clients more slowly than 1.5.2 (205 against 242
  requests/s here). The cause was not investigated.

The delays which the current version adds on purpose (to failed logins without
a `User-Agent`, and to repeated failures for one user name) are not part of
these numbers, see above.
