<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class BFStopViewIPInfo extends HtmlView
{
	public function display($tpl = null)
	{
		$input = Factory::getApplication()->input;
		$this->ipAddress = $input->getString("ipaddress");
		/*
		$error = false;
		set_error_handler(function() { $error = true; });
		$details = json_decode(file_get_contents("https://freegeoip.net/json/".$this->ipAddress));
		restore_error_handler();
		// TODO: provide alternatives, e.g.
		// - different service, e.g.:
		//        or http://ipinfo.io/ipAddress/json (might cost money if you do more requests)
		//        through $details = json_decode(file_get_contents("url"));
		// - local file
		//     e.g. http://lite.ip2location.com/

		if ($error || is_null($details))
		{
		*/
			$this->ipInfo = Text::_("COM_BFSTOP_NO_IPINFO_AVAILABLE");
		/*
		}
		else
		{
			$this->ipInfo = "<pre>".Text::sprintf("COM_BFSTOP_IPINFO_DETAILS",
				$details->ip,
				$details->country_code,
				$details->country_name,
				$details->region_name,
				$details->city,
				$details->zip_code,
				$details->latitude,
				$details->longitude)."</pre>";
		}
		*/
		$this->addToolbar();
		parent::display($tpl);
	}
	protected function addToolbar()
	{
		ToolbarHelper::title(Text::sprintf('COM_BFSTOP_HEADING_IPINFO', $this->ipAddress), 'bfstop');
		ToolbarHelper::divider();
		ToolbarHelper::back();
	}
}
