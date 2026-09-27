<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Language\Text;

$offset = (int) $this->pagination->limitstart;
foreach ($this->items as $i => $item): ?>
<tr>
	<td><?php echo $offset + $i + 1; ?></td>
	<td>
		<a href="<?php echo $this->escape($this->getFailedLoginsLink($item->username)); ?>"><?php echo $this->escape($item->username); ?></a>
		<?php if ($item->user_id): ?>
		<span class="badge bg-danger" title="<?php echo Text::_('COM_BFSTOP_USERNAMESTATS_EXISTING_ACCOUNT_DESC'); ?>"><?php echo Text::_('COM_BFSTOP_USERNAMESTATS_EXISTING_ACCOUNT'); ?></span>
		<?php endif; ?>
	</td>
	<td>
		<div class="d-flex align-items-center gap-2">
			<div class="progress flex-grow-1" role="progressbar" aria-hidden="true" style="min-width: 5em;">
				<div class="progress-bar" style="width: <?php echo $this->getBarWidth($item->attempts); ?>%"></div>
			</div>
			<span><?php echo (int) $item->attempts; ?></span>
		</div>
	</td>
	<td><?php echo $item->first_attempt; ?></td>
	<td><?php echo $item->last_attempt; ?></td>
</tr>
<?php endforeach;
