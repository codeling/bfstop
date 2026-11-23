<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Language\Text;

// the stored values which keep every change of the settings from being
// saved (see SettingsAudit): shown in the form of each step, whose saving
// saves the fixes with it
if (count($this->blocking) === 0)
{
	return;
}
?>
<div class="alert alert-warning">
	<h3 class="alert-heading h5"><?php echo Text::_('COM_BFSTOP_SETUP_PANEL_HEADING'); ?></h3>
	<p><?php echo Text::_('COM_BFSTOP_SETUP_PANEL_DESC'); ?></p>
	<table class="table table-sm mb-0">
		<thead>
			<tr>
				<th scope="col"><?php echo Text::_('COM_BFSTOP_SETUP_PANEL_SETTING'); ?></th>
				<th scope="col"><?php echo Text::_('COM_BFSTOP_SETUP_PANEL_STORED'); ?></th>
				<th scope="col"><?php echo Text::_('COM_BFSTOP_SETUP_PANEL_PROBLEM'); ?></th>
				<th scope="col"><?php echo Text::_('COM_BFSTOP_SETUP_PANEL_FIX'); ?></th>
			</tr>
		</thead>
		<tbody>
<?php foreach ($this->blocking as $field => $entry): ?>
			<tr>
				<th scope="row"><?php echo $this->escape($entry['label']); ?></th>
				<td><code><?php echo $this->escape($entry['value']); ?></code></td>
				<td><?php echo $entry['message']; ?></td>
				<td>
					<label class="visually-hidden" for="fix-<?php echo $this->escape($field); ?>"><?php echo Text::_('COM_BFSTOP_SETUP_PANEL_FIX'); ?></label>
					<input type="text" class="form-control form-control-sm" id="fix-<?php echo $this->escape($field); ?>"
						name="fix[<?php echo $this->escape($field); ?>]" value="<?php echo $this->escape(is_array($entry['fix']) ? implode(',', $entry['fix']) : $entry['fix']); ?>">
				</td>
			</tr>
<?php endforeach; ?>
		</tbody>
	</table>
</div>
