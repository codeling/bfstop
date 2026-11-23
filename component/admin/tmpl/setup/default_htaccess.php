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

$htaccess = $this->htaccess;
$this->stepButtons = array('htaccess', 'setup.upgradeHtaccess', 'COM_BFSTOP_SETUP_HTACCESS_RUN');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_HTACCESS'); ?></h2>
<?php if ($htaccess['present']): ?>
<div class="alert alert-danger"><?php echo Text::sprintf('COM_BFSTOP_SETUP_HTACCESS_INTRO', '<code>'.$this->escape($htaccess['file']).'</code>'); ?></div>
<div class="row">
	<div class="col-md-6">
		<h3 class="h5"><?php echo Text::_('COM_BFSTOP_SETUP_HTACCESS_CURRENT'); ?></h3>
		<pre><code><?php echo $this->escape(implode("\n", $htaccess['current'])); ?></code></pre>
	</div>
	<div class="col-md-6">
		<h3 class="h5"><?php echo Text::_('COM_BFSTOP_SETUP_HTACCESS_PROPOSED'); ?></h3>
		<pre><code><?php echo $this->escape(implode("\n", $htaccess['proposed'])); ?></code></pre>
	</div>
</div>
<?php else: ?>
<p class="alert alert-success"><?php echo Text::sprintf('COM_BFSTOP_SETUP_HTACCESS_FINE', '<code>'.$this->escape($htaccess['file']).'</code>'); ?></p>
<?php endif; ?>
<form method="post" action="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=htaccess'); ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<?php echo $this->loadTemplate('buttons'); ?>
</form>
