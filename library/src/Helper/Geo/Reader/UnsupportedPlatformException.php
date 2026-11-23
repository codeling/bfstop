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
 * The platform cannot decode a database value or offset.
 *
 * @final
 */
// phpcs:ignore PSR2.Classes.ClassDeclaration, Squiz.WhiteSpace.ScopeClosingBrace.ContentBefore
class UnsupportedPlatformException extends \RuntimeException {}
