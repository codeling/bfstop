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

?>
<form method="post" name="adminForm" id="adminForm">
	<input type="hidden" name="task" value="settings.testNotify" />
	<?php echo HTMLHelper::_('form.token'); ?>
	<div class="row">
		<div id="j-main-container" class="span10 j-toggle-main col-md-10">
			<div class="message" >
				<?php echo Text::sprintf('SETTINGS_VIEW_HINT', Route::_('index.php?option=com_plugins&view=plugins', false)); ?>
			</div>
		</div>
	</div>
</form>
