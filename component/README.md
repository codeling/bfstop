# com\_bfstop
## Brute Force Stop Joomla! Component

Main author: Bernhard Fröhler

This is the component part of the [Brute Force Stop Joomla! Extension package](https://extensions.joomla.org/extensions/extension/access-a-security/site-security/brute-force-stop/).

For detailed information, as well as instructions on how to download, install and configure Brute Force Stop, please browse to [the bfstop wiki](https://github.com/codeling/bfstop/wiki).

If you find any issues, please report them at [the bfstop issue tracker](https://github.com/codeling/bfstop/issues).

If you are interested in the source code, or want to contribute, please check [the bfstop source repository](https://github.com/codeling/com\_bfstop) at github.

For any further questions, don't hesitate to contact me under bfstop@bfroehler.info

## 2.0.0: Joomla 5/6 migration

Version 2.0.0 migrates the component to PSR-4 namespaced classes
(`Codeling\Component\Bfstop`) and drops support for Joomla 3/4. Notable change
for integrators: the frontend `router.php` was removed, since all of its
build/parse logic was already commented out and effectively a no-op; Joomla's
default component router is used instead, with no change in behaviour.

BFStop's configuration was also consolidated into this component's Settings
view (Components -> Brute Force Stop -> Settings). It used to be split
between here and the plugin's own Options tab in the Plugin Manager; the
plugin manifest no longer defines any configuration fields, so the
component's Settings view is now the single place to configure BFStop
(enabling/disabling the plugin itself still happens in the Plugin Manager,
as with any Joomla plugin).

