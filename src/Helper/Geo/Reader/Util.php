<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Vendored from maxmind-db/reader 1.14.0 (see Geo/Reader.php for details).
 * Original work Copyright (C) MaxMind, Inc., licensed under the
 * Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
**/

declare(strict_types=1);

namespace Codeling\Plugin\System\Bfstop\Helper\Geo\Reader;

defined('_JEXEC') or die;

class Util
{
    /**
     * @param resource    $stream
     * @param int<0, max> $numberOfBytes
     */
    public static function read($stream, int $offset, int $numberOfBytes): string
    {
        if ($numberOfBytes === 0) {
            return '';
        }
        if (fseek($stream, $offset) === 0) {
            $value = fread($stream, $numberOfBytes);

            // Check that the number of bytes read is the number asked for.
            if ($value !== false && \strlen($value) === $numberOfBytes) {
                return $value;
            }
        }

        throw new InvalidDatabaseException(
            'The MaxMind DB file contains bad data'
        );
    }
}
