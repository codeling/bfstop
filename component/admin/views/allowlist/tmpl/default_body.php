<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\HTML\HTMLHelper;

foreach ($this->items as $i => $item): ?>
<tr>
	<td><?php echo HTMLHelper::_('grid.id', $i, $item->id); ?></td>
	<td><?php echo $item->id; ?></td>
	<td><a href="<?php echo BFStopLinkHelper::getIpInfoLink($item->ipaddress);?>"><?php echo $item->ipaddress; ?></a></td>
	<td><?php if (str_contains($item->ipaddress, "/")) { $rng = cidrToRange($item->ipaddress); echo($rng[0]."-".$rng[1]." (".numOfAddresses($item->ipaddress).")"); } ?></td>
	<td><?php echo $item->notes; ?></td>
</tr>
<?php endforeach;
