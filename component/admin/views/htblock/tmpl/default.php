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
<form method="post" name="adminForm" id="adminForm">
	<fieldset class="adminform">
		<legend><?php echo Text::_('COM_BFSTOP_BLOCK_DETAILS'); ?></legend>
		<ul class="adminformlist">
<?php foreach($this->form->getFieldset() as $field): ?>
			<li><?php echo $field->label; echo $field->input; ?></li>
<?php endforeach; ?>
		</ul>
	</fieldset>
	<input type="hidden" name="task" value="htblock.edit" />
	<?php echo HTMLHelper::_('form.token'); ?>
</form>
