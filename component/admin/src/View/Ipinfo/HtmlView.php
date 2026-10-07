<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Ipinfo;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Plugin\System\Bfstop\Helper\GeoHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	public function display($tpl = null)
	{
		$input = Factory::getApplication()->getInput();
		$this->ipAddress = $input->getString("ipaddress");

		// looked up locally via a MaxMind .mmdb database (see GeoHelper) -
		// this used to call the free freegeoip.net API, which was shut down
		// in 2018 (see issue #169); a local lookup also avoids sending every
		// blocked visitor's IP address to a third party.
		$geoDbPath = ParamHelper::get('geoDbPath', 'params', '');
		$details = GeoHelper::getCityDetails(LogHelper::getLogger(), $geoDbPath, $this->ipAddress);

		if ($details === null)
		{
			$this->ipInfo = Text::_("COM_BFSTOP_NO_IPINFO_AVAILABLE");
		}
		else
		{
			// the address comes from the request and the rest from the GeoIP
			// database file, so none of it is trusted to be free of markup
			$this->ipInfo = "<pre>".$this->escape(Text::sprintf("COM_BFSTOP_IPINFO_DETAILS",
				$details->ip,
				$details->countryCode,
				$details->countryName,
				$details->region,
				$details->city,
				$details->postalCode,
				$details->latitude,
				$details->longitude))."</pre>";
		}
		$this->addToolbar();
		parent::display($tpl);
	}

	protected function addToolbar()
	{
		// the toolbar title is output as HTML
		ToolbarHelper::title(Text::sprintf('COM_BFSTOP_HEADING_IPINFO', $this->escape((string) $this->ipAddress)), 'bfstop');
		ToolbarHelper::divider();
		ToolbarHelper::back();
	}
}
