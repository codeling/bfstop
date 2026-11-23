<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Vendored from maxmind-db/reader 1.15.0 (see Geo/Reader.php for details).
 * Original work Copyright (C) MaxMind, Inc., licensed under the
 * Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
**/

declare(strict_types=1);

namespace Codeling\Library\Bfstop\Helper\Geo\Reader;

defined('_JEXEC') or die;

/**
 * This class should be thrown when unexpected data is found in the database.
 *
 * @final
 */
// phpcs:disable
class InvalidDatabaseException extends \Exception {}
