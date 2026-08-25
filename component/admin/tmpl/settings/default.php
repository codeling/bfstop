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
	<input type="hidden" name="task" value="" />
	<?php echo HTMLHelper::_('form.token'); ?>
	<div class="row">
		<div id="j-main-container" class="span10 j-toggle-main col-md-10">
<?php foreach ($this->form->getFieldsets() as $fieldset): ?>
			<fieldset class="adminform">
				<legend><?php echo Text::_(!empty($fieldset->label) ? $fieldset->label : ucfirst($fieldset->name)); ?></legend>
				<ul class="adminformlist">
<?php foreach ($this->form->getFieldset($fieldset->name) as $field): ?>
					<li><?php echo $field->label; echo $field->input; ?></li>
<?php endforeach; ?>
				</ul>
			</fieldset>
<?php endforeach; ?>
			<fieldset class="adminform">
				<legend><?php echo Text::_('COM_BFSTOP_SETTINGS_VERSION_FIELDSET_LABEL'); ?></legend>
				<ul class="adminformlist">
					<li><?php echo Text::sprintf('COM_BFSTOP_SETTINGS_VERSION_COMPONENT',
						$this->componentVersion !== null ? $this->componentVersion : Text::_('COM_BFSTOP_SETTINGS_VERSION_UNKNOWN')); ?></li>
					<li><?php echo Text::sprintf('COM_BFSTOP_SETTINGS_VERSION_PLUGIN',
						$this->pluginVersion !== null ? $this->pluginVersion : Text::_('COM_BFSTOP_SETTINGS_VERSION_UNKNOWN')); ?></li>
				</ul>
			</fieldset>
		</div>
	</div>
</form>
