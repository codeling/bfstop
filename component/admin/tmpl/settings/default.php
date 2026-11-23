<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Service\Setup\ProxyMismatch;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

?>
<form method="post" name="adminForm" id="adminForm">
	<input type="hidden" name="task" value="" />
	<?php echo HTMLHelper::_('form.token'); ?>
	<div class="row">
		<div id="j-main-container" class="span10 j-toggle-main col-md-10">
			<?php echo HTMLHelper::_('uitab.startTabSet', 'bfstopSettingsTabs', ['active' => 'basic', 'recall' => true, 'breakpoint' => 768]); ?>
<?php foreach ($this->form->getFieldsets() as $fieldset): ?>
			<?php echo HTMLHelper::_('uitab.addTab', 'bfstopSettingsTabs', $fieldset->name, Text::_(!empty($fieldset->label) ? $fieldset->label : ucfirst($fieldset->name))); ?>
				<fieldset id="fieldset-<?php echo $this->escape($fieldset->name); ?>" class="options-form">
<?php if (!empty($fieldset->description)): ?>
					<div class="tab-description alert alert-info">
						<span class="icon-info-circle" aria-hidden="true"></span>
						<?php echo Text::_($fieldset->description); ?>
					</div>
<?php endif; ?>
<?php if ($fieldset->name === 'proxy' && $this->addressCheck !== ''): ?>
					<div class="alert alert-info">
						<h3 class="alert-heading h5"><?php echo Text::_('COM_BFSTOP_SETTINGS_ADDRESS_CHECK_HEADING'); ?></h3>
						<?php echo $this->addressCheck; ?>
					</div>
<?php foreach ($this->proxyMismatches as $mismatch): ?>
					<div class="alert <?php echo $mismatch['information'] ? 'alert-info' : 'alert-warning'; ?>">
						<?php echo $mismatch['code'] === ProxyMismatch::LoadBalancer
							? Text::_('COM_BFSTOP_SETUP_LOADBALANCER_'.strtoupper($mismatch['hint']))
							: Text::_('COM_BFSTOP_SETUP_MISMATCH_'.strtoupper($mismatch['code'])); ?>
					</div>
<?php endforeach; ?>
					<p>
						<a class="btn btn-secondary" href="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=proxy'); ?>">
							<?php echo Text::_('COM_BFSTOP_SETUP_RERUN_PROXY_CHECK'); ?>
						</a>
					</p>
<?php endif; ?>
					<div class="form-grid">
						<?php echo $this->form->renderFieldset($fieldset->name); ?>
					</div>
				</fieldset>
			<?php echo HTMLHelper::_('uitab.endTab'); ?>
<?php endforeach; ?>
			<?php echo HTMLHelper::_('uitab.addTab', 'bfstopSettingsTabs', 'version', Text::_('COM_BFSTOP_SETTINGS_VERSION_FIELDSET_LABEL')); ?>
				<fieldset id="fieldset-version" class="options-form">
					<ul class="adminformlist">
						<li><?php echo Text::sprintf('COM_BFSTOP_SETTINGS_VERSION_COMPONENT',
							$this->componentVersion !== null ? $this->componentVersion : Text::_('COM_BFSTOP_SETTINGS_VERSION_UNKNOWN')); ?></li>
						<li><?php echo Text::sprintf('COM_BFSTOP_SETTINGS_VERSION_PLUGIN',
							$this->pluginVersion !== null ? $this->pluginVersion : Text::_('COM_BFSTOP_SETTINGS_VERSION_UNKNOWN')); ?></li>
					</ul>
				</fieldset>
			<?php echo HTMLHelper::_('uitab.endTab'); ?>
			<?php echo HTMLHelper::_('uitab.endTabSet'); ?>
		</div>
	</div>
</form>
