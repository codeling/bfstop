# The BFStop package

What users install: one Joomla! package (`pkg_bfstop-<version>.zip`) with the
plugin (this repository) and the component
([codeling/com_bfstop](https://github.com/codeling/com_bfstop)) in it. It used
to have a repository of its own, codeling/pkg_bfstop, with the extension zips
committed into it by hand.

- `pkg_bfstop.xml`: the package manifest.
- `script.php`: the package's installer script; refuses Joomla! < 5.0 and
  PHP < 8.1 before anything is installed (sites on Joomla! 4 stay with 1.5).
- `update.xml`: the update server's collection file
  (`https://bfstop.bfroehler.info/update.xml`, which installed sites ask).
- `build.sh`: builds the zips.

## Building

    package/build.sh <com_bfstop checkout> [<output directory>]

zips the plugin and the component with their own `deploy.sh`, from copies of
the checkouts, and puts them and the package into `build/` (or the given
directory), with a `SHA256SUMS-<version>` file. Nothing is committed: CI builds
the package for every push and pull request and keeps it as an artifact of the
run ("bfstop-<version>"), installs it in all its Joomla! sites and updates a
site of the previous release with it (see `tests/README.md`).

## Versions

Plugin, component and package are released together, with one version number,
written in `bfstop.xml` of both repositories, in `pkg_bfstop.xml` and in the
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

`update.xml` is not part of this: it says what the update server offers, which
is the latest *release*, never a test release.

## Releasing

1. Set the versions (both repositories) and, for a release, the date of the
   CHANGELOG entry; merge.
2. Tag com_bfstop, then this repository, with the version (`2.1.0-rc1`,
   `2.1.0`) and push the tags.
3. `.github/workflows/release.yml` runs on the tag: it checks the versions
   against the tag (`check-versions.php --release`), builds from the two tags,
   runs all of CI on that build (every Joomla site installs the package, a site
   of the previous release is updated with it), and creates a **draft** GitHub
   release with the three zips, the SHA-256 sums and notes from the CHANGELOG
   (`release-notes.php`). A test release is marked as pre-release and says so
   in its notes.
4. Check the draft and publish it.
5. Only for a release: update the update server (`update.xml` and the
   details file) - and put the release into `tests/ci/previous-release.sha256`,
   so that CI tests the update from it from then on.
