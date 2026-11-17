<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Language\Text;

?>
	<tr>
		<td colspan="7">
			<?php echo Text::_('COM_BFSTOP_LIMIT').$this->pagination->getLimitBox(); ?>
			<?php echo $this->pagination->getListFooter(); ?>
		</td>
	</tr>
