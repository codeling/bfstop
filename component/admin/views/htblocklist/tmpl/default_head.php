<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\HTML\HTMLHelper;

?>
<tr class="sortable">
	<th width="20">
		<input
			type="checkbox"
			name="toggle"
			value=""
			onclick="checkAll(<?php echo count($this->items); ?>);"
		/>
	</th>
	<th>
		<?php echo HTMLHelper::_('grid.sort',
			'COM_BFSTOP_HEADING_IPADDRESS',
			'ipaddress',
			$this->sortDirection,
			$this->sortColumn); ?>
	</th>
</tr>
