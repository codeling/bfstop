<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Service\Setup\ProxyCleanup;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

$findings = $this->cleanup;
$list = fn (array $entries) => '<code>'.implode('</code>, <code>', array_map(array($this, 'escape'), $entries)).'</code>';
$this->stepButtons = array('cleanup', 'setup.cleanup', 'COM_BFSTOP_SETUP_CLEANUP_RUN');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_CLEANUP'); ?></h2>
<p><?php echo Text::_('COM_BFSTOP_SETUP_CLEANUP_INTRO'); ?></p>
<?php if (!(bool) $this->setting('useProxy')): ?>
<p class="alert alert-info"><?php echo Text::_('COM_BFSTOP_SETUP_CLEANUP_NO_PROXY'); ?></p>
<?php elseif (!ProxyCleanup::anything($findings)): ?>
<p class="alert alert-success"><?php echo Text::_('COM_BFSTOP_SETUP_CLEANUP_NOTHING'); ?></p>
<?php else: ?>
<ul>
	<li><?php echo Text::sprintf('COM_BFSTOP_SETUP_CLEANUP_BLOCKS', count($findings['blocks'])); ?>
		<?php echo count($findings['blocks']) > 0 ? $list($findings['blocks']) : ''; ?></li>
	<li><?php echo Text::sprintf('COM_BFSTOP_SETUP_CLEANUP_FAILEDLOGINS', array_sum($findings['failedLogins'])); ?>
		<?php echo count($findings['failedLogins']) > 0 ? $list(array_keys($findings['failedLogins'])) : ''; ?></li>
	<li><?php echo Text::sprintf('COM_BFSTOP_SETUP_CLEANUP_OFFENCES', count($findings['offences'])); ?></li>
	<li><?php echo Text::sprintf('COM_BFSTOP_SETUP_CLEANUP_KNOWNIPS', count($findings['knownIps'])); ?></li>
</ul>
<?php if (count($findings['allowList']) > 0): ?>
<div class="alert alert-warning">
	<?php echo Text::sprintf('COM_BFSTOP_SETUP_CLEANUP_ALLOWLIST', $list($findings['allowList']),
		Route::_('index.php?option=com_bfstop&view=allowlist')); ?>
</div>
<?php endif; ?>
<?php endif; ?>
<form method="post" action="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=cleanup'); ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<?php echo $this->loadTemplate('buttons'); ?>
</form>
