<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LinkHelper;

foreach ($this->items as $i => $item): ?>
<tr>
	<td><?php echo (int) $item->id; ?></td>
	<td><a href="<?php echo $this->escape(LinkHelper::getIpInfoLink($item->ipaddress));?>"><?php echo $this->escape($item->ipaddress); ?></a></td>
	<td><?php echo $this->escape($item->logtime); ?></td>
	<td><?php echo $this->escape($item->username); ?></td>
	<td><?php echo $this->getOriginName($item->origin); ?></td>
</tr>
<?php endforeach;
