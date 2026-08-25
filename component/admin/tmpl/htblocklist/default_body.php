<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LinkHelper;
use Joomla\CMS\HTML\HTMLHelper;

foreach ($this->items as $i => $ipaddress): ?>
<tr>
	<td><?php echo HTMLHelper::_('grid.id', $i, $ipaddress); ?></td>
	<td><a href="<?php echo $this->escape(LinkHelper::getIpInfoLink($ipaddress));?>"><?php echo $this->escape($ipaddress); ?></a></td>
</tr>
<?php endforeach;
