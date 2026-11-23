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

$badges = array('done' => 'bg-success', 'skipped' => 'bg-secondary', 'pending' => 'bg-warning text-dark');
?>
<div class="row">
	<div class="col-lg-3">
		<nav aria-label="<?php echo Text::_('COM_BFSTOP_SETUP_STEPS'); ?>">
			<ol class="list-group list-group-numbered mb-3">
<?php foreach ($this->pages as $page): ?>
<?php $status = $this->pageStatus($page); ?>
				<li class="list-group-item d-flex justify-content-between align-items-start<?php echo $page === $this->page ? ' active' : ''; ?>">
					<a class="ms-2 me-auto<?php echo $page === $this->page ? ' link-light' : ''; ?>"
						href="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page='.$page); ?>"
						<?php echo $page === $this->page ? 'aria-current="step"' : ''; ?>>
						<?php echo Text::_('COM_BFSTOP_SETUP_PAGE_'.strtoupper($page)); ?>
					</a>
<?php if ($status !== null): ?>
					<span class="badge rounded-pill <?php echo $badges[$status]; ?>"><?php echo Text::_('COM_BFSTOP_SETUP_STATUS_'.strtoupper($status)); ?></span>
<?php endif; ?>
				</li>
<?php endforeach; ?>
			</ol>
		</nav>
		<p class="alert <?php echo $this->pluginEnabled && $this->setup->isCompleted() ? 'alert-success' : ($this->pluginEnabled ? 'alert-warning' : 'alert-danger'); ?>">
			<?php echo Text::_($this->pluginEnabled
				? ($this->setup->isCompleted() ? 'COM_BFSTOP_SETUP_STATE_ACTIVE' : 'COM_BFSTOP_SETUP_STATE_ENABLED_NOT_COMPLETED')
				: 'COM_BFSTOP_SETUP_STATE_INACTIVE'); ?>
		</p>
	</div>
	<div class="col-lg-9">
		<?php echo $this->loadTemplate($this->page); ?>
	</div>
</div>
