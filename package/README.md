# The BFStop package

What users install: one Joomla! package (`pkg_bfstop-<version>.zip`) with the
library (`library/`), the system plugin (`plugin/`), the task plugin (`task/`),
the quick icon plugin (`quickicon/`), the console plugin (`console/`) and the
component (`component/`) of this repository in it. The library comes
first in `pkg_bfstop.xml`: Joomla installs the extensions of a package in that
order (and uninstalls them in the reverse one), and the others use it. It used to have a repository of its
own, codeling/pkg_bfstop, with the extension zips committed into it by hand;
the component had one too, codeling/com_bfstop, until it was merged into this
repository (with its history) for 2.0.0.

- `pkg_bfstop.xml`: the package manifest.
- `script.php`: the package's installer script; refuses Joomla! < 5.4 and
  PHP < 8.2 before anything is installed (sites on Joomla! 4 stay with 1.5).
- `update-server.php`: writes the files of the update server
  (`update.xml` and `update-pkg.xml` at `https://bfstop.de`, which
  installed sites ask) from the GitHub releases, see "The update server".
- `build.sh`: builds the zips.

## Building

    package/build.sh [<output directory>]

zips the system plugin and the component with their own `deploy.sh`
(`plugin/deploy.sh zip`, `component/deploy.sh zip`), from a copy of their
directories, and the library and the task, quick icon and console plugins
from their directories (whose manifests are called `bfstop.xml` too: Joomla finds a plugin's
namespace in `<element>.xml`), and puts them and the package into `build/` (or the given
directory), with a `SHA256SUMS-<version>` file. Nothing is committed: CI builds
the package for every push and pull request and keeps it as an artifact of the
run ("bfstop-<version>"), installs it in all its Joomla! sites and updates a
site of the previous release with it (see `tests/README.md`).

## Versions

Plugin, component and package are released together, with one version number,
written in `library/bfstop.xml`, `plugin/bfstop.xml`, `task/bfstop.xml`, `quickicon/bfstop.xml`, `console/bfstop.xml`, `component/bfstop.xml`, `package/pkg_bfstop.xml` and in the
first entry of `CHANGELOG` - which says `(unreleased)` until the release, then
the date. `tests/lint/check-versions.php` checks that they agree (CI runs it,
and `build.sh` refuses to build otherwise). The `deploy.sh` scripts take the
version from their manifest.

A version is `X.Y.Z`, or `X.Y.Z-betaN` / `-rcN` / `-alphaN` for a **test
release**. A test release carries that version in the manifests (so testers see
what they have installed), and the CHANGELOG entry stays the one of the release
it leads to (`2.1.0 (unreleased)` for `2.1.0-rc1`). Joomla sorts them before the
release (`2.1.0-beta1 < 2.1.0-rc1 < 2.1.0`), so a site with a test release is
updated to the release normally.

The update server is not part of this: it offers the latest *release* of each
version line, never a test release.

## Releasing

1. Set the versions and, for a release, the date of the CHANGELOG entry;
   merge.
2. Tag the merge with the version (`2.1.0-rc1`, `2.1.0`) and push the tag.
3. `.github/workflows/release.yml` runs on the tag: it checks the versions
   against the tag (`check-versions.php --release`), builds from the tag,
   runs all of CI on that build (every Joomla site installs the package, a site
   of the previous release is updated with it), and creates a **draft** GitHub
   release with the zips, the SHA-256 sums and notes from the CHANGELOG
   (`release-notes.php`). A test release is marked as pre-release and says so
   in its notes. The zips and the sums get a build provenance attestation
   (`actions/attest-build-provenance`): anybody can check that a zip was built
   by this workflow, from the tag's commit, with
   `gh attestation verify pkg_bfstop-<version>.zip --repo codeling/bfstop`.
4. Check the draft and publish it.
5. Publishing the release (or changing or unpublishing it) updates the update
   server by itself, see below. Only for a release: put it into
   `tests/ci/previous-release.sha256`, so that CI tests the update from it from
   then on.

## The update server

`https://bfstop.de` is served by GitHub Pages and deployed by
`.github/workflows/pages.yml`: the page in `site/`, and the two files the
installed extensions ask for new versions, which `update-server.php` writes
from the releases on GitHub (`gh api repos/codeling/bfstop/releases`):

- `update.xml`, the collection (the manifests of the plugins, the component and
  the package point at it), which points at
- `update-pkg.xml`, with one update per version line: the newest published
  release of 1.x for Joomla! 4 and 5.0-5.3, of 2.x for Joomla! 5.4 and 6 (its
  `targetplatform` and `php_minimum`). Drafts and pre-releases (test releases)
  are never offered, and a release of a major version newer than the lines in
  `updateServerLines()` makes the generator fail - decide which Joomla!
  versions it is for first; releases older than the first line (0.9.x) are
  not offered. The SHA-256 is the one GitHub has for the package
  asset.

The workflow runs when a release is published, edited, unpublished or deleted,
when `site/` or the generator change on `main`, and by hand ("Run workflow").
Publishing a test release changes nothing in the files, but is a harmless way to
see the workflow work.

Setting it up (once, by the repository owner): *Settings → Pages → Source:
GitHub Actions*, and the custom domain `bfstop.de` there (then *Enforce
HTTPS*, once the certificate is issued). At the DNS provider, for the apex
domain `bfstop.de`: `A` records to `185.199.108.153`, `185.199.109.153`,
`185.199.110.153` and `185.199.111.153` (and `AAAA` records to
`2606:50c0:8000::153`, `2606:50c0:8001::153`, `2606:50c0:8002::153` and
`2606:50c0:8003::153`) - or an `ALIAS`/`ANAME` record to `codeling.github.io`
if the provider has them; `www.bfstop.de` can be a `CNAME` to
`codeling.github.io` (GitHub then redirects it). The current addresses are in
GitHub's documentation, "Managing a custom domain for your GitHub Pages site".
Verifying the domain for the account (*Settings → Pages* of the account; a
`TXT` record) keeps others from claiming it. Only `main` may deploy to the
`github-pages` environment (its default); `release` events start the workflow
on `main` for that reason.

### The old domain, bfstop.bfroehler.info

Every site which has BFStop 1.x (and a 2.0 test release, if the manifests of
that one were not changed) asks `https://bfstop.bfroehler.info/update.xml`, and
has to be offered 2.x from there. A GitHub Pages site has only *one* custom
domain, so `bfstop.bfroehler.info` can't be pointed at it as well: a `CNAME`
to `codeling.github.io` for a host which isn't the site's custom domain is
answered with a 404. Whatever answers for `bfstop.bfroehler.info` has to keep
serving `update.xml` and `update-pkg.xml` (or redirect to `bfstop.de`; check
with a real site that Joomla! follows it, which is H3 in #250) - do not
switch that host off.
