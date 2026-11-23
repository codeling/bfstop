<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\DurationHelper;
use Codeling\Component\Bfstop\Administrator\Model\SetupModel;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

// what keeps protection from being activated, besides the values the panel fixes
$missing = array_values(array_diff($this->missing, array('blockingValues')));
$completed = $this->setup->completedAt();
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_SUMMARY'); ?></h2>
<?php if ($completed !== null): ?>
<p class="alert <?php echo $this->pluginEnabled ? 'alert-success' : 'alert-warning'; ?>">
	<?php echo Text::sprintf($this->pluginEnabled ? 'COM_BFSTOP_SETUP_SUMMARY_COMPLETED' : 'COM_BFSTOP_SETUP_SUMMARY_COMPLETED_DISABLED',
		HTMLHelper::_('date', $completed, Text::_('DATE_FORMAT_LC2'))); ?>
</p>
<?php endif; ?>
<ul>
<?php foreach (array_intersect_key(SetupModel::PageSteps, array_flip($this->pages)) as $page => $step): ?>
	<li>
		<a href="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page='.$page); ?>"><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_'.strtoupper($page)); ?></a>:
		<?php echo Text::_('COM_BFSTOP_SETUP_STATUS_'.strtoupper($this->setup->status($step))); ?>
	</li>
<?php endforeach; ?>
</ul>
<p><?php echo Text::sprintf('COM_BFSTOP_SETUP_SUMMARY_SETTINGS', (int) $this->setting('blockNumber'),
	DurationHelper::toReadable((int) $this->setting('checkInterval')), DurationHelper::toReadable((int) $this->setting('blockDuration'))); ?></p>
<?php if ($this->setup->mode() === 'upgrade'): ?>
<p><?php echo Text::_('COM_BFSTOP_SETUP_SUMMARY_CHANGED_DEFAULTS'); ?></p>
<ul>
<?php foreach (array('ACCOUNT', 'RISK', 'IPV6', 'LOG', 'DELAY', 'SCHEDULER') as $change): ?>
	<li><?php echo Text::_('COM_BFSTOP_SETUP_SUMMARY_DEFAULT_'.$change); ?></li>
<?php endforeach; ?>
</ul>
<?php elseif (!in_array('ratelimit', $this->pages, true)): ?>
<p><?php echo Text::_('COM_BFSTOP_SETUP_RATELIMIT_'.$this->rateLimitAdvice()); ?></p>
<?php endif; ?>
<?php if ($this->loadBalancerHint !== null): ?>
<p class="alert alert-info"><?php echo Text::_('COM_BFSTOP_SETUP_LOADBALANCER_'.strtoupper($this->loadBalancerHint)); ?></p>
<?php endif; ?>
<div class="alert alert-info"><?php echo Text::_('COM_BFSTOP_SETUP_REMINDER'); ?></div>
<?php foreach ($missing as $reason): ?>
<p class="alert alert-warning"><?php echo Text::_('COM_BFSTOP_SETUP_MISSING_'.strtoupper($reason)); ?></p>
<?php endforeach; ?>
<form method="post" action="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=summary'); ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<?php echo $this->loadTemplate('panel'); ?>
	<button type="submit" name="task" value="setup.activate" class="btn btn-success btn-lg" <?php echo count($missing) > 0 ? 'disabled' : ''; ?>>
		<?php echo Text::_('COM_BFSTOP_SETUP_ACTIVATE'); ?>
	</button>
</form>
