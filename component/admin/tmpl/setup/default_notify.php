<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;


use Codeling\Component\Bfstop\Administrator\Model\SetupModel;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

$this->stepButtons = array('notify', 'setup.saveFields', 'COM_BFSTOP_SETUP_SAVE');
$action = Route::_('index.php?option=com_bfstop&view=setup&page=notify');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_NOTIFY'); ?></h2>
<p><?php echo Text::_('COM_BFSTOP_SETUP_NOTIFY_INTRO'); ?></p>
<?php if ($this->liveSiteNote !== ''): ?>
<div class="alert alert-warning">
	<?php echo $this->liveSiteNote; ?>
	<a href="<?php echo $action; ?>"><?php echo Text::_('COM_BFSTOP_SETUP_CHECK_AGAIN'); ?></a>
</div>
<?php endif; ?>
<?php if ($this->notifyMeaningChanged): ?>
<div class="alert alert-warning"><?php echo Text::_('COM_BFSTOP_SETUP_NOTIFY_MEANING'); ?></div>
<?php endif; ?>
<form method="post" action="<?php echo $action; ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<div class="options-form">
<?php foreach (SetupModel::StepFields['notify'] as $field): ?>
		<?php echo $this->settingsForm->renderField($field, 'params'); ?>
<?php endforeach; ?>
	</div>
	<?php echo $this->loadTemplate('panel'); ?>
	<?php echo $this->loadTemplate('buttons'); ?>
</form>
