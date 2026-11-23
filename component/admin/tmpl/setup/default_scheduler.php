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

$facts = $this->scheduler;
$this->stepButtons = array('scheduler', 'setup.acknowledge', 'COM_BFSTOP_SETUP_UNDERSTOOD');
$active = count(array_filter($facts['tasks'], fn ($task) => (int) $task->state === 1)) > 0;
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_SCHEDULER'); ?></h2>
<p><?php echo Text::_('COM_BFSTOP_SETUP_SCHEDULER_INTRO'); ?></p>
<ul>
	<li><?php echo Text::_($facts['plugin'] ? 'COM_BFSTOP_SETUP_SCHEDULER_PLUGIN_ON' : 'COM_BFSTOP_SETUP_SCHEDULER_PLUGIN_OFF'); ?></li>
<?php if (count($facts['tasks']) === 0): ?>
	<li><?php echo Text::_('COM_BFSTOP_SETUP_SCHEDULER_NO_TASK'); ?></li>
<?php endif; ?>
<?php foreach ($facts['tasks'] as $task): ?>
	<li><?php echo Text::sprintf((int) $task->state === 1 ? 'COM_BFSTOP_SETUP_SCHEDULER_TASK_ON' : 'COM_BFSTOP_SETUP_SCHEDULER_TASK_OFF',
		$this->escape((string) $task->title), $this->escape((string) ($task->last_execution ?? '-')),
		$this->escape((string) ($task->next_execution ?? '-'))); ?></li>
<?php endforeach; ?>
	<li><?php echo Text::_($facts['lazy'] ? 'COM_BFSTOP_SETUP_SCHEDULER_LAZY_ON' : 'COM_BFSTOP_SETUP_SCHEDULER_LAZY_OFF'); ?></li>
</ul>
<?php if (!$facts['plugin'] || !$active): ?>
<p class="alert alert-warning"><?php echo Text::_('COM_BFSTOP_SETUP_SCHEDULER_FALLBACK'); ?></p>
<?php endif; ?>
<p>
	<a href="<?php echo Route::_('index.php?option=com_scheduler&view=tasks'); ?>"><?php echo Text::_('COM_BFSTOP_SETUP_SCHEDULER_TASKS_LINK'); ?></a> |
	<a href="<?php echo Route::_('index.php?option=com_plugins&view=plugins&filter[folder]=task'); ?>"><?php echo Text::_('COM_BFSTOP_SETUP_SCHEDULER_PLUGINS_LINK'); ?></a> |
	<a href="<?php echo Route::_('index.php?option=com_config&view=component&component=com_scheduler'); ?>"><?php echo Text::_('COM_BFSTOP_SETUP_SCHEDULER_OPTIONS_LINK'); ?></a>
</p>
<form method="post" action="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=scheduler'); ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<?php echo $this->loadTemplate('buttons'); ?>
</form>
