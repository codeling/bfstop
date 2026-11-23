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
use Joomla\CMS\Router\Route;

$facts = $this->privacy;
$action = Route::_('index.php?option=com_bfstop&view=setup&page=privacy');
$this->stepButtons = array('privacy', 'setup.saveFields', 'COM_BFSTOP_SETUP_SAVE');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_PRIVACY'); ?></h2>
<p><?php echo $facts['count'] > 0
	? Text::sprintf('COM_BFSTOP_SETUP_PRIVACY_FAILEDLOGINS', $facts['count'], $this->escape((string) $facts['oldest']))
	: Text::_('COM_BFSTOP_SETUP_PRIVACY_NO_FAILEDLOGINS'); ?></p>
<form method="post" action="<?php echo $action; ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<div class="options-form">
		<?php echo $this->settingsForm->renderField('deleteOld', 'params'); ?>
		<?php echo $this->settingsForm->renderField('unknownUsernameMode', 'params'); ?>
	</div>
	<?php echo $this->loadTemplate('panel'); ?>
	<?php echo $this->loadTemplate('buttons'); ?>
</form>
<div class="card mt-3">
	<div class="card-body">
		<h3 class="card-title h5"><?php echo Text::_('COM_BFSTOP_SETUP_HASHING_HEADING'); ?></h3>
		<p><?php echo Text::_('COM_BFSTOP_SETUP_HASHING_DESC'); ?></p>
		<form method="post" action="<?php echo $action; ?>">
			<?php echo HTMLHelper::_('form.token'); ?>
			<button type="submit" name="task" value="setup.hashUsernames" class="btn btn-secondary">
				<?php echo Text::_($this->hashing !== null ? 'COM_BFSTOP_SETUP_HASHING_CONTINUE' : 'COM_BFSTOP_SETUP_HASHING_RUN'); ?>
			</button>
		</form>
		<p class="mt-3 mb-0"><?php echo Text::sprintf('COM_BFSTOP_SETUP_PRIVACY_LOG', HTMLHelper::_('number.bytes', $facts['logBytes']),
			Route::_('index.php?option=com_bfstop&view=log')); ?></p>
	</div>
</div>
