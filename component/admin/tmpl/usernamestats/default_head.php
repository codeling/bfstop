<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;

?>
<tr class="sortable">
	<th><?php echo Text::_('COM_BFSTOP_HEADING_RANK'); ?></th>
	<th>
		<?php echo HTMLHelper::_('grid.sort',
			'COM_BFSTOP_HEADING_USERNAME',
			's.username',
			$this->sortDirection,
			$this->sortColumn); ?>
	</th>
	<th>
		<?php echo HTMLHelper::_('grid.sort',
			'COM_BFSTOP_HEADING_FAILED_ATTEMPTS',
			's.attempts',
			$this->sortDirection,
			$this->sortColumn); ?>
	</th>
	<th>
		<?php echo HTMLHelper::_('grid.sort',
			'COM_BFSTOP_HEADING_FIRST_ATTEMPT',
			's.first_attempt',
			$this->sortDirection,
			$this->sortColumn); ?>
	</th>
	<th>
		<?php echo HTMLHelper::_('grid.sort',
			'COM_BFSTOP_HEADING_LAST_ATTEMPT',
			's.last_attempt',
			$this->sortDirection,
			$this->sortColumn); ?>
	</th>
</tr>
