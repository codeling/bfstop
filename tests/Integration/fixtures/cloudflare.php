<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// The router of the PHP web server of CloudflareRangesTest: lists of ranges
// as cloudflare.com serves them, and what else could come back.
switch (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH))
{
	case '/ips-v4':
		echo "173.245.48.0/20\n103.21.244.0/22\n";
		break;
	case '/ips-v6':
		echo "2400:cb00::/32\n2606:4700::/32";
		break;
	case '/redirect':
		header('Location: /ips-v4', true, 302);
		break;
	case '/big':
		// a few valid entries in a lot of whitespace, without saying how long it is
		header('Content-Type: text/plain');
		echo "198.51.100.0/24\n";
		for ($i = 0; $i < 1000; ++$i)
		{
			echo str_repeat(' ', 1024);
			flush();
		}
		echo "\n192.0.2.0/24\n";
		break;
	case '/wide':
		echo "0.0.0.0/0\n";
		break;
	default:
		http_response_code(404);
}
