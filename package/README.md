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

Plugin, component and package are released together, with one version number.
It is written in `bfstop.xml` of both repositories, in `pkg_bfstop.xml` and
`update.xml`, and in the first entry of `CHANGELOG`, which says `(unreleased)`
until the release, then the date. `tests/lint/check-versions.php` checks that
they agree (CI runs it, and `build.sh` refuses to build otherwise);
`--release=<tag>` additionally checks them against the tag and requires the
CHANGELOG date. The `deploy.sh` scripts take the version from their manifest.
