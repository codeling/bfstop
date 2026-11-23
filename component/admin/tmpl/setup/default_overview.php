<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

$setup = $this->setup;
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_OVERVIEW'); ?></h2>
<?php if ($setup->disabledReason() !== null && !$setup->isCompleted()): ?>
<div class="alert alert-danger">
	<?php echo Text::_($setup->disabledReason() === 'loadbalancer'
		? 'COM_BFSTOP_SETUP_OVERVIEW_DISABLED_LOADBALANCER' : 'COM_BFSTOP_SETUP_OVERVIEW_DISABLED_PROXY'); ?>
</div>
<?php endif; ?>
<?php if ($setup->mode() === 'upgrade'): ?>
<p><?php echo Text::sprintf('COM_BFSTOP_SETUP_OVERVIEW_UPGRADE', $this->escape((string) $setup->from())); ?></p>
<ul>
<?php if ($setup->fromBefore200()): ?>
	<li><?php echo Text::_('COM_BFSTOP_SETUP_OVERVIEW_DID_SETTINGS'); ?></li>
	<li><?php echo Text::sprintf('COM_BFSTOP_SETUP_OVERVIEW_DID_BLOCKMODE',
		Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_'.strtoupper($this->setting('blockMode')))); ?></li>
	<li><?php echo Text::_('COM_BFSTOP_SETUP_OVERVIEW_DID_API'); ?></li>
	<li><?php echo Text::_('COM_BFSTOP_SETUP_OVERVIEW_DID_ADDRESSES'); ?></li>
	<li><?php echo Text::_('COM_BFSTOP_SETUP_OVERVIEW_DID_MAINTENANCE'); ?></li>
<?php endif; ?>
	<li><?php echo Text::_($setup->htaccessNotRewritten()
		? 'COM_BFSTOP_SETUP_OVERVIEW_DID_HTACCESS_FAILED' : 'COM_BFSTOP_SETUP_OVERVIEW_DID_HTACCESS'); ?></li>
<?php if ($setup->delaysRemoved()): ?>
	<li><?php echo Text::_('COM_BFSTOP_SETUP_OVERVIEW_DID_DELAYS'); ?></li>
<?php endif; ?>
</ul>
<?php else: ?>
<p><?php echo Text::_('COM_BFSTOP_SETUP_OVERVIEW_INSTALL'); ?></p>
<?php endif; ?>
<p><?php echo Text::_('COM_BFSTOP_SETUP_OVERVIEW_STEPS'); ?></p>
<p>
	<a class="btn btn-primary" href="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=proxy'); ?>">
		<?php echo Text::_('COM_BFSTOP_SETUP_START'); ?>
	</a>
</p>
