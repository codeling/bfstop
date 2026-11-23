<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use Codeling\Library\Bfstop\Service\Setup\ProxyMismatch;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

$detected = $this->detected;
$useProxy = (bool) $this->setting('useProxy');
$input = $this->proxyInput ?? array();
$choice = $input['choice'] ?? (($useProxy || ProxyDetector::needsProxySettings($detected['scenario'])) ? 'proxy' : 'none');
$header = (string) (($input['header'] ?? '') !== '' ? $input['header']
	: ($useProxy ? $this->setting('proxyHeaderSource') : ($this->proposal['proxyHeaderSource'] ?? 'HTTP_X_FORWARDED_FOR')));
$trusted = (string) ($input['trusted'] ?? ($useProxy ? $this->setting('proxyIpAddress') : ($this->proposal['proxyIpAddress'] ?? '')));
$needsProxy = ProxyDetector::needsProxySettings($detected['scenario']);
$unsupportedOnly = $detected['scenario'] === ProxyDetector::Unsupported;
$shorten = fn ($value) => mb_strlen($value, 'UTF-8') > 200 ? mb_substr($value, 0, 200, 'UTF-8').'…' : $value;
$action = Route::_('index.php?option=com_bfstop&view=setup&page=proxy');
?>
<h2><?php echo Text::_('COM_BFSTOP_SETUP_PAGE_PROXY'); ?></h2>
<p><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_INTRO'); ?></p>

<?php foreach (ProxyMismatch::open($this->mismatches) as $mismatch): ?>
<div class="alert <?php echo $mismatch['information'] ? 'alert-info' : 'alert-warning'; ?>">
	<p><?php echo $mismatch['code'] === ProxyMismatch::LoadBalancer
		? Text::_('COM_BFSTOP_SETUP_LOADBALANCER_'.strtoupper($mismatch['hint']))
		: Text::_('COM_BFSTOP_SETUP_MISMATCH_'.strtoupper($mismatch['code'])); ?></p>
	<form method="post" action="<?php echo $action; ?>" class="mb-0">
		<input type="hidden" name="fingerprint" value="<?php echo $this->escape($mismatch['fingerprint']); ?>">
		<?php echo HTMLHelper::_('form.token'); ?>
		<button type="submit" name="task" value="setup.dismiss" class="btn btn-sm btn-outline-secondary">
			<?php echo Text::_('COM_BFSTOP_SETUP_DISMISS'); ?>
		</button>
	</form>
</div>
<?php endforeach; ?>

<?php if (count($this->suspicious) > 0): ?>
<div class="alert alert-warning">
	<?php echo Text::sprintf('COM_BFSTOP_SETUP_PROXY_SUSPICIOUS_BLOCKS',
		'<code>'.implode('</code>, <code>', array_map(array($this, 'escape'), $this->suspicious)).'</code>',
		Route::_('index.php?option=com_bfstop&view=blocklist')); ?>
</div>
<?php endif; ?>

<div class="card mb-3">
	<div class="card-body">
		<h3 class="card-title h5"><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_DETECTED'); ?></h3>
		<ul>
			<li><?php echo Text::sprintf($detected['remoteNonPublic'] ? 'COM_BFSTOP_SETUP_PROXY_REMOTE_PRIVATE' : 'COM_BFSTOP_SETUP_PROXY_REMOTE_PUBLIC',
				'<code>'.$this->escape($detected['remote']).'</code>'); ?></li>
<?php foreach ($detected['supported'] as $key => $value): ?>
			<li><?php echo Text::sprintf('COM_BFSTOP_SETTINGS_ADDRESS_CHECK_HEADER', '<code>'.$this->escape(IpHelper::headerName($key)).'</code>',
				'<code>'.$this->escape($shorten($value)).'</code>'); ?></li>
<?php endforeach; ?>
<?php foreach ($detected['unsupported'] as $key => $name): ?>
			<li><?php echo Text::sprintf('COM_BFSTOP_SETUP_PROXY_HEADER_UNSUPPORTED', '<code>'.$this->escape($name).'</code>'); ?></li>
<?php endforeach; ?>
<?php if (count($detected['supported']) + count($detected['unsupported']) === 0): ?>
			<li><?php echo Text::_('COM_BFSTOP_SETTINGS_ADDRESS_CHECK_NO_HEADER'); ?></li>
<?php endif; ?>
		</ul>
		<p class="mb-0"><strong><?php echo Text::_('COM_BFSTOP_SETUP_SCENARIO_'.$detected['scenario']); ?></strong></p>
	</div>
</div>

<?php if (count($detected['unsupported']) > 0): ?>
<div class="alert alert-warning">
	<p><?php echo Text::sprintf('COM_BFSTOP_SETUP_UNSUPPORTED', '<code>'.$this->escape(implode(', ', $detected['unsupported'])).'</code>'); ?></p>
	<p><?php echo Text::_(count($detected['supported']) > 0 ? 'COM_BFSTOP_SETUP_UNSUPPORTED_USE_OTHER' : 'COM_BFSTOP_SETUP_UNSUPPORTED_FIX'); ?></p>
	<p class="mb-0"><a href="<?php echo $this->escape($this->issueUrl); ?>" target="_blank" rel="noopener noreferrer"><?php echo Text::_('COM_BFSTOP_SETUP_UNSUPPORTED_ISSUE'); ?></a></p>
</div>
<?php endif; ?>
<?php if ($detected['cloudflare'] || $header === IpHelper::CloudflareHeader): ?>
<div class="alert alert-warning"><?php echo Text::_('COM_BFSTOP_SETUP_CLOUDFLARE_WARNING'); ?></div>
<?php endif; ?>

<form method="post" action="<?php echo $action; ?>" id="bfstop-setup-proxy">
	<?php echo HTMLHelper::_('form.token'); ?>
	<fieldset class="options-form">
		<legend><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_CHOICE'); ?></legend>
		<div class="form-check mb-3">
			<input class="form-check-input" type="radio" name="choice" value="none" id="choice-none"
				<?php echo $choice === 'none' ? 'checked' : ''; ?> <?php echo $unsupportedOnly ? 'disabled' : ''; ?>>
			<label class="form-check-label" for="choice-none"><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_CHOICE_NONE'); ?></label>
<?php if ($needsProxy && !$unsupportedOnly): ?>
			<div class="form-check mt-2">
				<input class="form-check-input" type="checkbox" name="acknowledge" value="1" id="acknowledge">
				<label class="form-check-label" for="acknowledge"><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_ACKNOWLEDGE'); ?></label>
			</div>
<?php endif; ?>
		</div>
		<div class="form-check">
			<input class="form-check-input" type="radio" name="choice" value="proxy" id="choice-proxy" <?php echo $choice === 'proxy' ? 'checked' : ''; ?>>
			<label class="form-check-label" for="choice-proxy"><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_CHOICE_PROXY'); ?></label>
			<div class="mt-2">
				<label class="form-label" for="proxy-header"><?php echo Text::_('PLG_SYSTEM_BFSTOP_PROXY_HEADER_SOURCE_LABEL'); ?></label>
				<select class="form-select" name="header" id="proxy-header">
<?php foreach (IpHelper::KnownProxyHeaders as $key): ?>
					<option value="<?php echo $this->escape($key); ?>" <?php echo $key === $header ? 'selected' : ''; ?>>
						<?php echo $this->escape(IpHelper::headerName($key)); ?><?php echo isset($detected['supported'][$key]) ? ' '.Text::_('COM_BFSTOP_SETUP_PROXY_HEADER_PRESENT') : ''; ?>
					</option>
<?php endforeach; ?>
				</select>
				<label class="form-label mt-2" for="proxy-trusted"><?php echo Text::_('PLG_SYSTEM_BFSTOP_PROXY_IP_LABEL'); ?></label>
				<textarea class="form-control" name="trusted" id="proxy-trusted" rows="3"><?php echo $this->escape($trusted); ?></textarea>
				<div class="form-text"><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_TRUSTED_DESC'); ?></div>
				<p class="mt-2">
					<button type="submit" name="task" value="setup.preview" class="btn btn-secondary"><?php echo Text::_('COM_BFSTOP_SETUP_PREVIEW'); ?></button>
<?php if ($detected['cloudflare']): ?>
					<button type="submit" name="task" value="setup.cloudflare" class="btn btn-outline-secondary"><?php echo Text::_('COM_BFSTOP_SETUP_CLOUDFLARE_FETCH'); ?></button>
<?php endif; ?>
				</p>
<?php if ($detected['cloudflare']): ?>
				<p class="form-text"><?php echo Text::_('COM_BFSTOP_SETUP_CLOUDFLARE_FETCH_DESC'); ?></p>
<?php endif; ?>
<?php if ($this->preview !== null): ?>
				<div id="preview" class="alert <?php echo $this->preview['problem'] === null ? 'alert-info' : 'alert-danger'; ?>">
<?php if ($this->preview['problem'] === null): ?>
					<p><?php echo Text::sprintf('COM_BFSTOP_SETUP_PREVIEW_QUESTION', '<strong><code>'.$this->escape($this->preview['address']).'</code></strong>'); ?></p>
					<input type="hidden" name="address" value="<?php echo $this->escape($this->preview['address']); ?>">
					<div class="form-check mb-0">
						<input class="form-check-input" type="checkbox" name="confirm" value="1" id="confirm">
						<label class="form-check-label" for="confirm"><?php echo Text::sprintf('COM_BFSTOP_SETUP_PREVIEW_CONFIRM', $this->escape($this->preview['address'])); ?></label>
					</div>
<?php else: ?>
					<p class="mb-0"><?php echo Text::_('COM_BFSTOP_SETUP_PREVIEW_PROBLEM_'.strtoupper($this->preview['problem'])); ?></p>
<?php endif; ?>
				</div>
<?php endif; ?>
			</div>
		</div>
	</fieldset>
	<?php echo $this->loadTemplate('panel'); ?>
	<div class="alert alert-info"><?php echo Text::_('COM_BFSTOP_SETUP_REMINDER'); ?></div>
	<button type="submit" name="task" value="setup.saveProxy" class="btn btn-primary"><?php echo Text::_('COM_BFSTOP_SETUP_PROXY_SAVE'); ?></button>
</form>
