<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;


use Joomla\CMS\Language\Text;

// the buttons of an optional step: $this->stepButtons = array(step, task of saving, its label)
list($step, $task, $label) = $this->stepButtons;
?>
<p class="mt-3">
<?php if ($task !== ''): ?>
	<button type="submit" name="task" value="<?php echo $this->escape($task); ?>" class="btn btn-primary"><?php echo Text::_($label); ?></button>
<?php endif; ?>
	<button type="submit" name="task" value="setup.skip" class="btn btn-outline-secondary" formnovalidate><?php echo Text::_('COM_BFSTOP_SETUP_SKIP'); ?></button>
	<input type="hidden" name="step" value="<?php echo $this->escape($step); ?>">
</p>
