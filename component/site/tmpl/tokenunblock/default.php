<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Language\Text;

?>
<h1><?php echo Text::_('COM_BFSTOP_UNBLOCKTOKEN_HEADING'); ?></h1>
<div> <?php echo $this->message; ?> </div>
<?php if ($this->showConfirmation): ?>
<?php // no action: posts to this very URL, which the plugin lets a blocked IP reach ?>
<form method="post">
	<input type="hidden" name="token" value="<?php echo $this->escape($this->token); ?>" />
	<button type="submit" class="btn btn-primary"><?php echo Text::_('COM_BFSTOP_UNBLOCKTOKEN_BUTTON'); ?></button>
</form>
<?php endif; ?>
