<?php

/**
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 */

// Bootstrap of phpstan (see phpstan.neon): the constants Joomla defines when
// it starts up (includes/defines.php), which the code under analysis uses.
// Their values don't matter, phpstan only needs to know they exist.

$constants = [
    '_JEXEC', 'JPATH_ROOT', 'JPATH_SITE', 'JPATH_BASE', 'JPATH_ADMINISTRATOR',
    'JPATH_PLUGINS', 'JPATH_LIBRARIES', 'JPATH_CONFIGURATION', 'JPATH_CACHE',
    'JPATH_API', 'JPATH_CLI', 'JPATH_THEMES',
];

foreach ($constants as $name) {
    if (!defined($name)) {
        define($name, $name === '_JEXEC' ? 1 : '/joomla');
    }
}
