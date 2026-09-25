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

$settingsUrl = Route::_('index.php?option=com_bfstop&view=settings', false);
?>
<div class="alert alert-info">
	<?php echo ($this->autoPurgeWeeks > 0)
		? Text::sprintf('COM_BFSTOP_FAILEDLOGIN_AUTOPURGE_ENABLED', $this->autoPurgeWeeks, $settingsUrl)
		: Text::sprintf('COM_BFSTOP_FAILEDLOGIN_AUTOPURGE_DISABLED', $settingsUrl); ?>
</div>
<form method="post" name="adminForm" id="adminForm">
	<input type="hidden" name="task" value="" />
	<?php echo HTMLHelper::_('form.token'); ?>
	<input type="hidden" name="filter_order" value="<?php echo $this->sortColumn; ?>" />
	<input type="hidden" name="filter_order_Dir" value="<?php echo $this->sortDirection; ?>" />
	<div class="row">
		<div id="j-main-container" class="span10 j-toggle-main col-md-10">
			<table class="adminlist table table-striped">
				<thead><?php echo $this->loadTemplate('head'); ?></thead>
				<tfoot><?php echo $this->loadTemplate('foot');?></tfoot>
				<tbody><?php echo $this->loadTemplate('body');?></tbody>
			</table>
		</div>
	</div>
</form>
<?php if ($this->canPurge): ?>
<div class="modal fade" id="bfstopPurgeModal" tabindex="-1" aria-labelledby="bfstopPurgeModalTitle" aria-hidden="true">
	<div class="modal-dialog">
		<form method="post" class="modal-content" action="<?php echo Route::_('index.php?option=com_bfstop&view=failedloginlist'); ?>">
			<div class="modal-header">
				<h3 class="modal-title" id="bfstopPurgeModalTitle"><?php echo Text::_('COM_BFSTOP_FAILEDLOGIN_PURGE_TITLE'); ?></h3>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?php echo Text::_('JCLOSE'); ?>"></button>
			</div>
			<div class="modal-body p-3">
				<p><?php echo Text::_('COM_BFSTOP_FAILEDLOGIN_PURGE_DESC'); ?></p>
				<label for="bfstopPurgeAge" class="form-label"><?php echo Text::_('COM_BFSTOP_FAILEDLOGIN_PURGE_AGE_LABEL'); ?></label>
				<input type="number" name="age" id="bfstopPurgeAge" class="form-control" min="1" step="1" value="30" required />
			</div>
			<div class="modal-footer">
				<input type="hidden" name="task" value="failedloginlist.purge" />
				<?php echo HTMLHelper::_('form.token'); ?>
				<button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><?php echo Text::_('JCANCEL'); ?></button>
				<button type="submit" class="btn btn-danger"><?php echo Text::_('COM_BFSTOP_FAILEDLOGIN_PURGE_CONFIRM'); ?></button>
			</div>
		</form>
	</div>
</div>
<?php endif; ?>
