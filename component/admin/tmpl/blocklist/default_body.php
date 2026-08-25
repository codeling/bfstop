<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\IpRangeHelper;
use Codeling\Component\Bfstop\Administrator\Helper\LinkHelper;
use Joomla\CMS\HTML\HTMLHelper;

foreach ($this->items as $i => $item): ?>
<tr>
	<td><?php echo HTMLHelper::_('grid.id', $i, $item->id); ?></td>
	<td><?php echo $item->id; ?></td>
	<td><a href="<?php echo $this->escape(LinkHelper::getIpInfoLink($item->ipaddress));?>"><?php echo $this->escape($item->ipaddress); ?></a></td>
	<td><?php if (str_contains($item->ipaddress, "/")) { $rng = IpRangeHelper::cidrToRange($item->ipaddress); echo($this->escape($rng[0]."-".$rng[1]." (".IpRangeHelper::numOfAddresses($item->ipaddress).")")); } ?></td>
	<td><?php echo $item->crdate; ?></td>
	<td><?php echo $this->convertDurationToReadable($item->duration); ?></td>
	<td><?php echo $this->getBlockedState($item); ?></td>
</tr>
<?php endforeach;
