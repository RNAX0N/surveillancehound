<?php
/*
 * SurveillanceHound — pfSense Services > SurveillanceHound page.
 *
 * Uses the pfSense package GUI helper (pkg_edit.php) to render the form
 * defined in /usr/local/pkg/hound.xml; we only need to add the
 * status + embedded-dashboard chrome around it.
 */
require_once("guiconfig.inc");
require_once("/usr/local/pkg/hound.inc");

$pgtitle = ["Services", "SurveillanceHound"];
$pglinks = ["", "@self"];
include("head.inc");

global $config;
$s = $config['installedpackages']['hound']['config'][0] ?? [];
$svc_running = (file_exists("/var/run/hound.pid"))
    ? trim(@file_get_contents("/var/run/hound.pid")) : "";
// posix_kill(pid, 0) is the canonical "is this pid alive?" probe — if the
// pidfile is stale, ESRCH lands as a PHP warning; @-suppress it.
$running = $svc_running !== ""
    && function_exists("posix_kill")
    && @posix_kill(intval($svc_running), 0);

$web_host = htmlspecialchars($s['web_host'] ?? '127.0.0.1');
$web_port = intval($s['web_port'] ?? 8080);
$dash_url = "http://{$web_host}:{$web_port}/";
?>

<style>
.hound-status { padding: 10px 14px; border-radius: 4px; margin-bottom: 14px;
                font-family: monospace; }
.hound-status.up    { background: #e9f7ee; border-left: 4px solid #28a745; }
.hound-status.down  { background: #fdecea; border-left: 4px solid #dc3545; }
.hound-iframe-wrap  { border: 1px solid #ccc; background: #03060d;
                      height: 720px; }
.hound-iframe-wrap iframe { width: 100%; height: 100%; border: 0;
                            display: block; }
</style>

<div class="hound-status <?= $running ? 'up' : 'down' ?>">
  <strong>Status:</strong>
  <?= $running ? "running (pid {$svc_running})" : "stopped" ?>
  &nbsp;|&nbsp;
  <a href="/pkg_edit.php?xml=hound.xml">Edit settings →</a>
  &nbsp;|&nbsp;
  <a href="<?= $dash_url ?>" target="_blank">Open dashboard ↗</a>
</div>

<div class="hound-iframe-wrap">
  <iframe src="<?= $dash_url ?>" title="SurveillanceHound dashboard"></iframe>
</div>

<p style="margin-top: 10px; color: #666;">
  Configure capture interface, camera IPs, baselining, snapshots and the
  dashboard bind in <a href="/pkg_edit.php?xml=hound.xml">Settings</a>.
  Saving regenerates <code>/usr/local/etc/hound.toml</code> and restarts
  the daemon.
</p>

<?php include("foot.inc"); ?>
