<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

$advice = $this->advice;
$server = Text::_('COM_BFSTOP_SETUP_SERVER_'.strtoupper($advice['server']));
$modes = array('loginonly', 'full', 'htaccess', 'off');
$htaccessName = Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_HTACCESS');
$fullName = Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_FULL');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_BLOCKMODE'); ?></h2>
<p><?php echo Text::sprintf('COM_BFSTOP_SETUP_BLOCKMODE_INTRO', $this->escape($server),
	Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_'.strtoupper($advice['mode']))); ?></p>
<?php foreach ($advice['warnings'] as $warning): ?>
<div class="alert <?php echo $warning === 'unprotected' ? 'alert-danger' : 'alert-warning'; ?>">
	<?php echo Text::sprintf('COM_BFSTOP_SETUP_BLOCKMODE_WARNING_'.strtoupper($warning), $htaccessName, $fullName); ?>
</div>
<?php endforeach; ?>

<form method="post" action="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=blockmode'); ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<fieldset class="options-form">
		<legend><?php echo Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_LABEL'); ?></legend>
<?php foreach ($modes as $mode): ?>
<?php $unfit = $mode === 'htaccess' && $advice['server'] === HtaccessHelper::ServerNginx; ?>
		<div class="form-check mb-2">
			<input class="form-check-input" type="radio" name="blockMode" value="<?php echo $mode; ?>" id="mode-<?php echo $mode; ?>"
				<?php echo !$unfit && $mode === $advice['recommended'] ? 'checked' : ''; ?> <?php echo $unfit ? 'disabled' : ''; ?>>
			<label class="form-check-label" for="mode-<?php echo $mode; ?>">
				<strong><?php echo Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_'.strtoupper($mode)); ?></strong>
				<?php echo $mode === $advice['recommended'] ? '<span class="badge bg-success">'.Text::_('COM_BFSTOP_SETUP_RECOMMENDED').'</span>' : ''; ?>
				<br><span class="form-text"><?php echo Text::_('COM_BFSTOP_SETUP_BLOCKMODE_'.strtoupper($mode).'_DESC'); ?></span>
			</label>
		</div>
<?php endforeach; ?>
		<div class="form-check mt-3">
			<input class="form-check-input" type="checkbox" name="confirmOff" value="1" id="confirm-off">
			<label class="form-check-label" for="confirm-off"><?php echo Text::_('COM_BFSTOP_SETUP_BLOCKMODE_CONFIRM_OFF'); ?></label>
		</div>
	</fieldset>
<?php if ($advice['server'] === HtaccessHelper::ServerNginx): ?>
	<div class="options-form">
		<label class="form-label" for="nginx-deny-file"><?php echo Text::_('COM_BFSTOP_SETTINGS_NGINX_DENY_FILE_LABEL'); ?></label>
		<input type="text" class="form-control" name="nginxDenyFile" id="nginx-deny-file"
			value="<?php echo $this->escape((string) $this->setting('nginxDenyFile')); ?>" placeholder="/etc/nginx/bfstop-deny.conf">
		<div class="form-text"><?php echo Text::_('COM_BFSTOP_SETTINGS_NGINX_DENY_FILE_DESC'); ?></div>
		<p class="form-text"><?php echo Text::_('COM_BFSTOP_SETUP_NGINX_INCLUDE'); ?></p>
		<pre><code>include <?php echo $this->escape((string) $this->setting('nginxDenyFile') !== '' ? (string) $this->setting('nginxDenyFile') : '/etc/nginx/bfstop-deny.conf'); ?>;</code></pre>
	</div>
<?php endif; ?>
	<?php echo $this->loadTemplate('panel'); ?>
	<button type="submit" name="task" value="setup.saveBlockMode" class="btn btn-primary"><?php echo Text::_('COM_BFSTOP_SETUP_BLOCKMODE_SAVE'); ?></button>
<?php if (in_array($advice['server'], array(HtaccessHelper::ServerApache, HtaccessHelper::ServerLiteSpeed), true)): ?>
	<button type="submit" name="task" value="setup.checkHtaccess" class="btn btn-outline-secondary"><?php echo Text::_('COM_BFSTOP_HTACCESS_CHECK'); ?></button>
<?php endif; ?>
</form>
