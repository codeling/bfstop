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

$this->stepButtons = array('parts', 'setup.saveFields', 'COM_BFSTOP_SETUP_SAVE');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_PARTS'); ?></h2>
<p><?php echo Text::_('COM_BFSTOP_SETUP_PARTS_INTRO'); ?></p>
<p><?php echo Text::sprintf('COM_BFSTOP_SETUP_PARTS_API_TOKENS', $this->apiTokenUsers); ?></p>
<form method="post" action="<?php echo Route::_('index.php?option=com_bfstop&view=setup&page=parts'); ?>">
	<?php echo HTMLHelper::_('form.token'); ?>
	<div class="options-form">
		<?php echo $this->settingsForm->renderField('enabledForOrigin', 'params'); ?>
	</div>
	<?php echo $this->loadTemplate('panel'); ?>
	<?php echo $this->loadTemplate('buttons'); ?>
</form>
