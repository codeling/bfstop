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

$this->stepButtons = array('rateLimit', 'setup.acknowledge', 'COM_BFSTOP_SETUP_UNDERSTOOD');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_RATELIMIT'); ?></h2>
<p><?php echo Text::_('COM_BFSTOP_SETUP_RATELIMIT_INTRO'); ?></p>
<div class="alert alert-info"><?php echo Text::_('COM_BFSTOP_SETUP_RATELIMIT_'.$this->rateLimitAdvice()); ?></div>
<form method="post" action="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=ratelimit'); ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<?php echo $this->loadTemplate('buttons'); ?>
</form>
