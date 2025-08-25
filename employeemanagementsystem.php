<?php
@session_start();
$root = __DIR__;
// Discover python in venv, then py -3, then python3/python
$venvPy = (stripos(PHP_OS, 'WIN') === 0)
    ? $root . DIRECTORY_SEPARATOR . 'venv' . DIRECTORY_SEPARATOR . 'Scripts' . DIRECTORY_SEPARATOR . 'python.exe'
    : $root . DIRECTORY_SEPARATOR . 'venv' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'python';
$pythonCandidates = [];
if (file_exists($venvPy)) { $pythonCandidates[] = $venvPy; }
if (stripos(PHP_OS, 'WIN') === 0) { $pythonCandidates[] = 'py -3'; $pythonCandidates[] = 'python'; }
$pythonCandidates[] = 'python3';
$python = null;
foreach ($pythonCandidates as $cand) {
  $cmd = (stripos($cand, ' ') !== false) ? $cand . ' -V' : escapeshellcmd($cand) . ' -V';
  @exec($cmd, $out, $rc);
  if ($rc === 0) { $python = $cand; break; }
}
if ($python === null) { $python = 'python3'; }

// Common env for helpers: resolve shared DB path robustly and export without replacing PATH/ENV
$resolvedDb = null;
// 1) Respect existing env if valid
$envDb = getenv('EMS_DB_PATH');
if ($envDb && file_exists($envDb)) { $resolvedDb = $envDb; }
// 2) Local monitoring.db
if (!$resolvedDb) {
  $localDb = $root . DIRECTORY_SEPARATOR . 'monitoring.db';
  if (file_exists($localDb) && filesize($localDb) > 0) { $resolvedDb = realpath($localDb); }
}
// 3) config.ini [Database] db_path
if (!$resolvedDb) {
  $cfgFile = $root . DIRECTORY_SEPARATOR . 'config.ini';
  if (file_exists($cfgFile)) {
    $ini = parse_ini_file($cfgFile, true, INI_SCANNER_TYPED);
    if (is_array($ini) && isset($ini['Database']) && isset($ini['Database']['db_path'])) {
      $dbp = $ini['Database']['db_path'];
      if ($dbp && is_string($dbp)) {
        if (preg_match('~^[A-Za-z]:\\\\|^/~', $dbp)) { // absolute (Windows or Unix)
          if (file_exists($dbp)) { $resolvedDb = $dbp; }
        } else {
          $candidate = realpath($root . DIRECTORY_SEPARATOR . $dbp);
          if ($candidate && file_exists($candidate)) { $resolvedDb = $candidate; }
        }
      }
    }
  }
}
// 4) Fallback to local path (may not exist)
if (!$resolvedDb) { $resolvedDb = $root . DIRECTORY_SEPARATOR . 'monitoring.db'; }
@putenv('EMS_DB_PATH=' . $resolvedDb);
// Share encryption key path for helpers
$keyPath = $root . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'master.key';
@putenv('SECURITY_MASTER_KEY_PATH=' . $keyPath);

// --- Web replica DB helpers (MySQL) ---
$mysqlHost = '127.0.0.1';
$mysqlDb   = 'ems_web';
$mysqlUser = 'root';
$mysqlPass = '';

function webdb_conn() {
  global $mysqlHost, $mysqlDb, $mysqlUser, $mysqlPass;
  static $pdo = null;
  if ($pdo) return $pdo;
  // Ensure database exists
  $bootstrap = new PDO('mysql:host=' . $mysqlHost . ';charset=utf8mb4', $mysqlUser, $mysqlPass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
  ]);
  $bootstrap->exec("CREATE DATABASE IF NOT EXISTS `" . $mysqlDb . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
  $bootstrap = null;
  // Connect to DB
  $dsn = 'mysql:host=' . $mysqlHost . ';dbname=' . $mysqlDb . ';charset=utf8mb4';
  $pdo = new PDO($dsn, $mysqlUser, $mysqlPass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
  ]);
  // init schema
  // Users and IM tables
  $pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS user_sessions (
    sid VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS im_threads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL,
    client_id VARCHAR(128) NULL,
    name VARCHAR(255) NULL,
    UNIQUE KEY uniq_sc (server_id, client_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS im_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    thread_id INT NOT NULL,
    sender_type VARCHAR(16) NOT NULL, -- 'user' or 'client'
    user_id INT NULL,
    client_id VARCHAR(128) NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_thread (thread_id),
    INDEX idx_created (created_at),
    FOREIGN KEY (thread_id) REFERENCES im_threads(id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128),
    base_url VARCHAR(255) NOT NULL,
    token_enc TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_sync_at DATETIME NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_clients (
    server_id INT NOT NULL, client_id VARCHAR(128), hostname VARCHAR(255), platform VARCHAR(64), status VARCHAR(32),
    last_seen VARCHAR(64), ip_address VARCHAR(64), logged_in_user VARCHAR(255), mac_address VARCHAR(64), uptime_seconds BIGINT NULL,
    INDEX idx_sc_server (server_id), INDEX idx_sc_client (client_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_sessions (
    server_id INT NOT NULL, id INT, client_id VARCHAR(128), created_at VARCHAR(64), expires_at VARCHAR(64), last_activity VARCHAR(64),
    INDEX idx_ss_server (server_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_captures (
    server_id INT NOT NULL, id INT, client_id VARCHAR(128), capture_timestamp VARCHAR(64), image_size INT, compression_ratio DOUBLE, processing_time_ms INT,
    INDEX idx_sc2_server (server_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_messages (
    server_id INT NOT NULL, id INT, client_id VARCHAR(128), direction VARCHAR(32), message TEXT, timestamp VARCHAR(64),
    INDEX idx_sm_server (server_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_fileops (
    server_id INT NOT NULL, id INT, client_id VARCHAR(128), operation_type VARCHAR(64), file_path TEXT, details TEXT, created_at VARCHAR(64),
    INDEX idx_sf_server (server_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_security (
    server_id INT NOT NULL, id INT, event_type VARCHAR(64), client_id VARCHAR(128), description TEXT, timestamp VARCHAR(64),
    INDEX idx_sec_server (server_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_client_logs (
    server_id INT NOT NULL,
    id INT,
    client_id VARCHAR(128),
    level VARCHAR(32),
    logger_name VARCHAR(255),
    module VARCHAR(255),
    func_name VARCHAR(255),
    line INT,
    created_at VARCHAR(64),
    message TEXT,
    INDEX idx_scl_server (server_id), INDEX idx_scl_client (client_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS snapshot_exec_results (
    server_id INT NOT NULL,
    id INT,
    client_id VARCHAR(128),
    command_id VARCHAR(128),
    cmd VARCHAR(255),
    exit_code INT,
    created_at VARCHAR(64),
    stdout TEXT,
    stderr TEXT,
    INDEX idx_ser_server (server_id), INDEX idx_ser_client (client_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  return $pdo;
}

function resolve_admin_creds($root){
  $token = getenv('EMS_ADMIN_TOKEN') ?: '';
  $port  = getenv('EMS_ADMIN_PORT') ?: '';
  if ($token === '' || $port === '') {
    $cfgFile = $root . DIRECTORY_SEPARATOR . 'config.ini';
    if (file_exists($cfgFile)) {
      $ini = @parse_ini_file($cfgFile, true, INI_SCANNER_TYPED);
      if (is_array($ini) && isset($ini['WebAdmin'])) {
        if ($token === '' && !empty($ini['WebAdmin']['admin_token'])) { $token = (string)$ini['WebAdmin']['admin_token']; }
        if ($port === '' && !empty($ini['WebAdmin']['admin_port'])) { $port = (string)$ini['WebAdmin']['admin_port']; }
      }
    }
  }
  if ($port === '') { $port = '9090'; }
  return [$token, $port];
}

function admin_forward($root, array $payload){
  list($token, $port) = resolve_admin_creds($root);
  $json = json_encode($payload);
  $headers = "Content-Type: application/json\r\n" . ($token?"X-Admin-Token: $token\r\n":'');
  $opts = [ 'http' => [ 'method' => 'POST', 'header' => $headers, 'content' => $json, 'timeout' => 3 ] ];
  $ctx = stream_context_create($opts);
  $resp = @file_get_contents("http://127.0.0.1:".$port, false, $ctx);
  if ($resp === false && function_exists('curl_init')) {
    $ch = curl_init('http://127.0.0.1:'.$port);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_HTTPHEADER=>array_filter(explode("\r\n", trim($headers))), CURLOPT_POSTFIELDS=>$json, CURLOPT_TIMEOUT=>3]);
    $resp = curl_exec($ch);
    curl_close($ch);
  }
  return $resp;
}

function enc_secret($plain) {
  $key = getenv('WEB_MASTER_KEY');
  if (!$key || strlen($key) < 16) return $plain; // store plaintext if no key
  $keyBin = substr(hash('sha256', $key, true), 0, 32);
  $iv = random_bytes(16);
  $ct = openssl_encrypt($plain, 'aes-256-cbc', $keyBin, OPENSSL_RAW_DATA, $iv);
  return base64_encode($iv . $ct);
}
function dec_secret($enc) {
  $key = getenv('WEB_MASTER_KEY');
  if (!$key || strlen($key) < 16) return $enc;
  $raw = base64_decode($enc, true);
  if ($raw === false || strlen($raw) < 17) return $enc;
  $iv = substr($raw, 0, 16); $ct = substr($raw, 16);
  $keyBin = substr(hash('sha256', $key, true), 0, 32);
  $pt = openssl_decrypt($ct, 'aes-256-cbc', $keyBin, OPENSSL_RAW_DATA, $iv);
  return $pt === false ? $enc : $pt;
}

$action = isset($_GET['action']) ? $_GET['action'] : 'ui';

function is_logged_in(){ return !empty($_SESSION['uid']); }
function csrf_token(){ if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); } return $_SESSION['csrf']; }
function require_auth_api(){ if (!is_logged_in()) { http_response_code(401); header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'auth required']); exit; } }

if ($action === 'login') {
    $pdo = webdb_conn();
    $count = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    $csrf = csrf_token();
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>EMS Login</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body class="bg-dark text-light">';
    echo '<div class="container py-5"><div class="row justify-content-center"><div class="col-md-5">';
    echo '<div class="card bg-secondary"><div class="card-body">';
    if ($count === 0) {
      echo '<h5 class="card-title">Create Admin</h5>';
      echo '<form method="post" action="?action=do_register_admin">';
      echo '<input type="hidden" name="csrf" value="'.$csrf.'">';
      echo '<div class="mb-3"><label class="form-label">Username</label><input class="form-control" name="username" required></div>';
      echo '<div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div>';
      echo '<button class="btn btn-primary w-100" type="submit">Create Admin</button>';
      echo '</form>';
    } else {
      echo '<h5 class="card-title">Login</h5>';
      echo '<form method="post" action="?action=do_login">';
      echo '<input type="hidden" name="csrf" value="'.$csrf.'">';
      echo '<div class="mb-3"><label class="form-label">Username</label><input class="form-control" name="username" required></div>';
      echo '<div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div>';
      echo '<button class="btn btn-primary w-100" type="submit">Login</button>';
      echo '</form>';
    }
    echo '</div></div></div></div></div></body></html>';
    exit;
}

if ($action === 'do_register_admin') {
    $pdo = webdb_conn();
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(400); echo 'Bad CSRF'; exit; }
    $count = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if ($count > 0) { header('Location: ?action=login'); exit; }
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    if ($u === '' || $p === '') { header('Location: ?action=login'); exit; }
    $hash = password_hash($p, PASSWORD_DEFAULT);
    $ins = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')");
    $ins->execute([$u, $hash]);
    $_SESSION['uid'] = (int)$pdo->lastInsertId();
    $_SESSION['uname'] = $u;
    header('Location: ?action=ui');
    exit;
}

if ($action === 'do_login') {
    $pdo = webdb_conn();
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(400); echo 'Bad CSRF'; exit; }
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    $sel = $pdo->prepare("SELECT id, password_hash FROM users WHERE username=? LIMIT 1");
    $sel->execute([$u]);
    $row = $sel->fetch();
    if ($row && password_verify($p, $row['password_hash'])) {
        $_SESSION['uid'] = (int)$row['id'];
        $_SESSION['uname'] = $u;
        $pdo->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$_SESSION['uid']]);
        header('Location: ?action=ui');
        exit;
    }
    header('Location: ?action=login');
    exit;
}

if ($action === 'logout') {
    session_destroy();
    header('Location: ?action=login');
    exit;
}

if ($action === 'frame') {
    if (!isset($_SESSION['uid'])) { http_response_code(401); echo json_encode(['ok'=>false]); exit; }
    $clientId = isset($_GET['client_id']) ? $_GET['client_id'] : '';
    $helper = $root . DIRECTORY_SEPARATOR . 'tools' . DIRECTORY_SEPARATOR . 'get_latest_frame.py';
    if ($clientId === '' || !file_exists($helper)) {
        http_response_code(404);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'missing client_id or helper']);
        exit;
    }
    $cmd = (stripos($python, ' ') !== false ? $python : escapeshellcmd($python)) . ' ' . escapeshellarg($helper) . ' ' . escapeshellarg($clientId);
    $descriptorspec = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $descriptorspec, $pipes, $root, null);
    if (!is_resource($proc)) { http_response_code(500); echo 'proc_open failed'; exit; }
    $img = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    foreach ($pipes as $p) { if (is_resource($p)) fclose($p); }
    $status = proc_close($proc);
    if (!$img) { http_response_code(404); header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>$err?:'no image']); exit; }
    // Detect mime (PNG/JPEG) by magic
    $ctype = 'application/octet-stream';
    if (strlen($img) >= 8 && substr($img, 0, 8) === "\x89PNG\x0D\x0A\x1A\x0A") { $ctype = 'image/png'; }
    elseif (strlen($img) >= 3 && substr($img, 0, 3) === "\xFF\xD8\xFF") { $ctype = 'image/jpeg'; }
    header('Content-Type: ' . $ctype);
    echo $img;
    exit;
}

if ($action === 'info') {
    header('Content-Type: application/json; charset=utf-8');
    if (!isset($_SESSION['uid'])) { echo json_encode(['ok'=>false,'error'=>'auth required']); exit; }
    $helper = $root . DIRECTORY_SEPARATOR . 'tools' . DIRECTORY_SEPARATOR . 'server_info.py';
    if (!file_exists($helper)) { echo json_encode(['ok' => false, 'error' => 'helper missing']); exit; }
    $cmd = (stripos($python, ' ') !== false ? $python : escapeshellcmd($python)) . ' ' . escapeshellarg($helper);
    $descriptorspec = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $process = proc_open($cmd, $descriptorspec, $pipes, $root, null);
    if (!is_resource($process)) { echo json_encode(['ok' => false, 'error' => 'proc_open failed']); exit; }
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    foreach ($pipes as $p) { if (is_resource($p)) fclose($p); }
    $code = proc_close($process);
    if (!$out) { echo json_encode(['ok'=>false,'error'=>$err?:'no output']); exit; }
    echo $out;
    exit;
}

if ($action === 'admin') {
    header('Content-Type: application/json; charset=utf-8');
    if (!isset($_SESSION['uid'])) { echo json_encode(['ok'=>false]); exit; }
    $raw = file_get_contents('php://input');
    if ($raw === false) { $raw = '{}'; }
    $payload = json_decode($raw ?: '{}', true);
    $resp = admin_forward($root, is_array($payload)?$payload:[]);
    echo $resp ?: json_encode(['ok'=>false]);
    exit;
}

if ($action === 'replica_overview') {
    header('Content-Type: application/json; charset=utf-8');
    if (!isset($_SESSION['uid'])) { echo json_encode(['ok'=>false,'error'=>'auth required']); exit; }
    try {
        $pdo = webdb_conn();
        $last = $pdo->query("SELECT last_sync_at FROM servers WHERE id=1")->fetchColumn();
        $counts = [
            'clients_count' => (int)$pdo->query("SELECT COUNT(*) FROM snapshot_clients WHERE server_id=1")->fetchColumn(),
            'sessions_count' => (int)$pdo->query("SELECT COUNT(*) FROM snapshot_sessions WHERE server_id=1")->fetchColumn(),
            'captures_count' => (int)$pdo->query("SELECT COUNT(*) FROM snapshot_captures WHERE server_id=1")->fetchColumn(),
            'messages_count' => (int)$pdo->query("SELECT COUNT(*) FROM snapshot_messages WHERE server_id=1")->fetchColumn(),
            'fileops_count' => (int)$pdo->query("SELECT COUNT(*) FROM snapshot_fileops WHERE server_id=1")->fetchColumn(),
            'security_count' => (int)$pdo->query("SELECT COUNT(*) FROM snapshot_security WHERE server_id=1")->fetchColumn(),
        ];
        $clients = $pdo->query("SELECT client_id, hostname, platform, status, last_seen, ip_address, logged_in_user, mac_address, uptime_seconds FROM snapshot_clients WHERE server_id=1 ORDER BY last_seen DESC LIMIT 200")->fetchAll();
        echo json_encode(['ok'=>true, 'last_sync_at'=>$last] + $counts + ['clients'=>$clients]);
    } catch (Exception $e) {
        echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
    }
    exit;
}

if ($action === 'download_updater_guide') {
    $file = $root . DIRECTORY_SEPARATOR . 'docs' . DIRECTORY_SEPARATOR . 'updater_guide.html';
    if (!file_exists($file)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Guide not found.';
        exit;
    }
    header('Content-Type: text/html; charset=utf-8');
    header('Content-Disposition: attachment; filename="updater_guide.html"');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

if ($action === 'sync') {
    header('Content-Type: application/json; charset=utf-8');
    if (!isset($_SESSION['uid'])) { echo json_encode(['ok'=>false,'error'=>'auth required']); exit; }
    try {
        // Pull via local Python helper to avoid HTTP/file wrappers
        $helper = $root . DIRECTORY_SEPARATOR . 'tools' . DIRECTORY_SEPARATOR . 'server_info.py';
        if (!file_exists($helper)) { echo json_encode(['ok'=>false,'error'=>'server_info helper missing']); exit; }
        $cmd = (stripos($python, ' ') !== false ? $python : escapeshellcmd($python)) . ' ' . escapeshellarg($helper);
        $descriptorspec = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = proc_open($cmd, $descriptorspec, $pipes, $root, null);
        if (!is_resource($proc)) { echo json_encode(['ok'=>false,'error'=>'proc_open failed']); exit; }
        $json = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        foreach ($pipes as $p) { if (is_resource($p)) fclose($p); }
        proc_close($proc);
        if (!$json) { echo json_encode(['ok'=>false,'error'=>$err?:'no output']); exit; }
        $data = json_decode($json, true);
        if (!$data || empty($data['ok'])) { echo json_encode(['ok'=>false,'error'=>'invalid response']); exit; }

        $serverId = 1;
        $pdo = webdb_conn();
        // Upsert local server row with base_url
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $dir  = rtrim(dirname($_SERVER['REQUEST_URI'] ?? '/'), '/\\');
        $base = $scheme . '://' . $host . $dir;
        $stmt = $pdo->prepare("INSERT INTO servers (id, name, base_url) VALUES (1, 'local', ?) ON DUPLICATE KEY UPDATE base_url=VALUES(base_url)");
        $stmt->execute([$base]);

        // Truncate old snapshots
        $pdo->exec("DELETE FROM snapshot_clients WHERE server_id = 1");
        $pdo->exec("DELETE FROM snapshot_sessions WHERE server_id = 1");
        $pdo->exec("DELETE FROM snapshot_captures WHERE server_id = 1");
        $pdo->exec("DELETE FROM snapshot_messages WHERE server_id = 1");
        $pdo->exec("DELETE FROM snapshot_fileops WHERE server_id = 1");
        $pdo->exec("DELETE FROM snapshot_security WHERE server_id = 1");
        $pdo->exec("DELETE FROM snapshot_client_logs WHERE server_id = 1");
        $pdo->exec("DELETE FROM snapshot_exec_results WHERE server_id = 1");

        // Insert rows using prepared statements
        $ins = $pdo->prepare("INSERT INTO snapshot_clients (server_id, client_id, hostname, platform, status, last_seen, ip_address, logged_in_user, mac_address, uptime_seconds) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        foreach (($data['clients'] ?? []) as $c) {
            $ins->execute([$c['client_id'] ?? '', $c['hostname'] ?? '', $c['platform'] ?? '', $c['status'] ?? '', $c['last_seen'] ?? '', $c['ip_address'] ?? '', $c['logged_in_user'] ?? '', $c['mac_address'] ?? '', $c['uptime_seconds'] ?? null]);
        }
        $ins2 = $pdo->prepare("INSERT INTO snapshot_sessions (server_id, id, client_id, created_at, expires_at, last_activity) VALUES (1, ?, ?, ?, ?, ?)");
        foreach (($data['sessions'] ?? []) as $s) {
            $ins2->execute([$s['id'] ?? null, $s['client_id'] ?? '', $s['created_at'] ?? '', $s['expires_at'] ?? '', $s['last_activity'] ?? '']);
        }
        $ins3 = $pdo->prepare("INSERT INTO snapshot_captures (server_id, id, client_id, capture_timestamp, image_size, compression_ratio, processing_time_ms) VALUES (1, ?, ?, ?, ?, ?, ?)");
        foreach (($data['screen_captures'] ?? []) as $sc) {
            $ins3->execute([$sc['id'] ?? null, $sc['client_id'] ?? '', $sc['capture_timestamp'] ?? '', $sc['image_size'] ?? null, $sc['compression_ratio'] ?? null, $sc['processing_time_ms'] ?? null]);
        }
        $ins4 = $pdo->prepare("INSERT INTO snapshot_messages (server_id, id, client_id, direction, message, timestamp) VALUES (1, ?, ?, ?, ?, ?)");
        foreach (($data['chat_messages'] ?? []) as $m) {
            $ins4->execute([$m['id'] ?? null, $m['client_id'] ?? '', $m['direction'] ?? '', $m['message'] ?? '', $m['timestamp'] ?? '']);
        }
        $ins5 = $pdo->prepare("INSERT INTO snapshot_fileops (server_id, id, client_id, operation_type, file_path, details, created_at) VALUES (1, ?, ?, ?, ?, ?, ?)");
        foreach (($data['file_operations'] ?? []) as $f) {
            $ins5->execute([$f['id'] ?? null, $f['client_id'] ?? '', ($f['operation_type'] ?? $f['operation'] ?? ''), $f['file_path'] ?? '', ($f['details'] ?? $f['status'] ?? ''), $f['created_at'] ?? '']);
        }
        $ins6 = $pdo->prepare("INSERT INTO snapshot_security (server_id, id, event_type, client_id, description, timestamp) VALUES (1, ?, ?, ?, ?, ?)");
        foreach (($data['security_logs'] ?? []) as $sl) {
            $ins6->execute([$sl['id'] ?? null, $sl['event_type'] ?? '', $sl['client_id'] ?? '', $sl['description'] ?? '', $sl['timestamp'] ?? '']);
        }
        $ins7 = $pdo->prepare("INSERT INTO snapshot_client_logs (server_id, id, client_id, level, logger_name, module, func_name, line, created_at, message) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        foreach (($data['client_logs'] ?? []) as $cl) {
            $ins7->execute([
              $cl['id'] ?? null,
              $cl['client_id'] ?? '',
              $cl['level'] ?? '',
              $cl['logger'] ?? '',
              $cl['module'] ?? '',
              $cl['function'] ?? '',
              $cl['line'] ?? 0,
              $cl['created_at'] ?? '',
              $cl['message'] ?? ''
            ]);
        }
        $ins8 = $pdo->prepare("INSERT INTO snapshot_exec_results (server_id, id, client_id, command_id, cmd, exit_code, created_at, stdout, stderr) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)");
        foreach (($data['exec_results'] ?? []) as $er) {
            $ins8->execute([
              $er['id'] ?? null,
              $er['client_id'] ?? '',
              $er['command_id'] ?? '',
              $er['cmd'] ?? '',
              isset($er['exit_code']) ? (int)$er['exit_code'] : null,
              $er['created_at'] ?? '',
              $er['stdout'] ?? '',
              $er['stderr'] ?? ''
            ]);
        }
        $pdo->exec("UPDATE servers SET last_sync_at = NOW() WHERE id = 1");
        echo json_encode(['ok'=>true,'synced'=>true]);
    } catch (Exception $e) {
        echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
    }
    exit;
}

if ($action === 'im_history') {
    if (!isset($_SESSION['uid'])) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'auth required']); exit; }
    header('Content-Type: application/json; charset=utf-8');
    try {
        $pdo = webdb_conn();
        $clientId = isset($_GET['client_id']) ? (string)$_GET['client_id'] : '';
        $serverId = 1;
        if ($clientId === '') { echo json_encode(['ok'=>false,'error'=>'client_id required']); exit; }
        // find or create thread
        $sel = $pdo->prepare("SELECT id FROM im_threads WHERE server_id=? AND client_id=? LIMIT 1");
        $sel->execute([$serverId, $clientId]);
        $tid = $sel->fetchColumn();
        if (!$tid) {
            $ins = $pdo->prepare("INSERT INTO im_threads (server_id, client_id, name) VALUES (?, ?, ?)");
            $ins->execute([$serverId, $clientId, $clientId]);
            $tid = (int)$pdo->lastInsertId();
        }
        $stmt = $pdo->prepare("SELECT m.id, m.sender_type, m.user_id, m.client_id, m.message, m.created_at FROM im_messages m WHERE m.thread_id=? ORDER BY m.created_at ASC, m.id ASC");
        $stmt->execute([$tid]);
        $rows = $stmt->fetchAll();
        echo json_encode(['ok'=>true,'messages'=>$rows]);
    } catch (Exception $e) {
        echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
    }
    exit;
}

if ($action === 'im_send') {
    if (!isset($_SESSION['uid'])) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'auth required']); exit; }
    header('Content-Type: application/json; charset=utf-8');
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '[]', true);
    $clientId = isset($data['client_id']) ? (string)$data['client_id'] : '';
    $message = isset($data['message']) ? (string)$data['message'] : '';
    if ($clientId === '' || $message === '') { echo json_encode(['ok'=>false,'error'=>'client_id and message required']); exit; }
    try {
        $pdo = webdb_conn();
        $serverId = 1;
        $sel = $pdo->prepare("SELECT id FROM im_threads WHERE server_id=? AND client_id=? LIMIT 1");
        $sel->execute([$serverId, $clientId]);
        $tid = $sel->fetchColumn();
        if (!$tid) {
            $ins = $pdo->prepare("INSERT INTO im_threads (server_id, client_id, name) VALUES (?, ?, ?)");
            $ins->execute([$serverId, $clientId, $clientId]);
            $tid = (int)$pdo->lastInsertId();
        }
        $ins2 = $pdo->prepare("INSERT INTO im_messages (thread_id, sender_type, user_id, client_id, message) VALUES (?, 'user', ?, ?, ?)");
        $ins2->execute([(int)$tid, (int)$_SESSION['uid'], $clientId, $message]);
        // Forward to local admin API for delivery to server->client
        $resp = admin_forward($root, ['command'=>'send_chat','client_id'=>$clientId,'message'=>$message]);
        $okForward = false;
        if ($resp !== false) {
            $j = json_decode($resp, true);
            if (is_array($j) && array_key_exists('ok', $j)) { $okForward = (bool)$j['ok']; } else { $okForward = true; }
        }
        echo json_encode(['ok'=> $okForward]);
    } catch (Exception $e) {
        echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
    }
    exit;
}

// UI
?>
<?php if (!isset($_SESSION['uid'])) { header('Location: ?action=login'); exit; } ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Employee Monitoring System</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #0f1115; color: #e5e7eb; }
    .navbar { background: #111827; }
    .card { background: #1f2937; border: 1px solid #374151; }
    .table { color: #e5e7eb; }
    .table thead th { color: #9ca3af; background: #111827; border-color: #374151; font-weight: 600; }
    .table td { background-color: #374151; color: #0dcaf0; height: 40px; }
    #clients-table.table tbody td { padding: 0.4rem 0.5rem; border-color: #374151; }
    #clients-table.table tbody tr:hover { background: rgba(37, 99, 235, 0.08); }
    /* Compact card body for clients table */
    .clients-body { padding: 10px 12px; max-height: 420px; overflow: auto; }
    /* Smaller preview cells to reduce row height */
    .preview { background: #111827; height: 120px; display: flex; align-items: center; justify-content: center; border: 1px solid #374151; border-radius: 6px; }
    .preview img { max-height: 110px; max-width: 100%; object-fit: contain; filter: drop-shadow(0 0 4px rgba(0,0,0,0.4)); }
    .nav-pills .nav-link.active { background-color: #2563eb; }
	#system-info { color: #f8f8ff !IMPORTANT; }
  </style>
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script>
    function postAdmin(cmd, payload, onOk){
      // Send to local admin HTTP on server via PHP relay for security
      $.ajax({
        url: 'employeemanagementsystem.php?action=admin',
        method: 'POST',
        data: JSON.stringify(Object.assign({command: cmd}, payload||{})),
        contentType: 'application/json',
        success: function(r){ try{ onOk && onOk(r); }catch(e){} },
        error: function(){ alert('Admin command failed'); }
      });
    }
  </script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark mb-4">
  <div class="container-fluid">
    <span class="navbar-brand">Employee Monitoring System</span>
    <div class="ms-auto">
      <span class="me-2 small">Logged in as: <?php echo htmlspecialchars($_SESSION['uname'] ?? 'user', ENT_QUOTES); ?></span>
      <a class="btn btn-outline-danger btn-sm" href="?action=logout">Logout</a>
      <a class="btn btn-outline-info btn-sm" href="employeemanagementsystem.php?action=download_updater_guide">Download Updater Guide</a>
    </div>
  </div>
</nav>

<div class="container-fluid">
  <ul class="nav nav-pills mb-3" id="ems-tabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="tab-overview" data-bs-toggle="pill" data-bs-target="#pane-overview" type="button" role="tab">Overview</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-servers" data-bs-toggle="pill" data-bs-target="#pane-servers" type="button" role="tab">Servers</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-sessions" data-bs-toggle="pill" data-bs-target="#pane-sessions" type="button" role="tab">Sessions</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-captures" data-bs-toggle="pill" data-bs-target="#pane-captures" type="button" role="tab">Captures</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-messages" data-bs-toggle="pill" data-bs-target="#pane-messages" type="button" role="tab">Messages</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-fileops" data-bs-toggle="pill" data-bs-target="#pane-fileops" type="button" role="tab">File Ops</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-security" data-bs-toggle="pill" data-bs-target="#pane-security" type="button" role="tab">Security</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-notify" data-bs-toggle="pill" data-bs-target="#pane-notify" type="button" role="tab">Notifications</button>
    </li>
  </ul>

  <div class="tab-content" id="ems-tabs-content">
    <!-- Servers -->
    <div class="tab-pane fade" id="pane-servers" role="tabpanel" aria-labelledby="tab-servers">
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span>Known Servers (replica DB)</span>
          <div>
            <button class="btn btn-sm btn-outline-secondary" id="btn-test-info">Test Info</button>
            <button class="btn btn-sm btn-outline-secondary" id="btn-test-sync">Test Sync</button>
            <button class="btn btn-sm btn-outline-primary" id="btn-sync">Sync This Server</button>
            <div class="d-inline-flex align-items-center ms-2">
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="checkbox" id="chk-auto-sync">
                <label class="form-check-label small" for="chk-auto-sync">Auto-sync</label>
              </div>
              <input type="number" min="1" step="1" value="5" id="sync-interval-min" class="form-control form-control-sm" style="width:70px" title="Minutes">
              <span class="ms-1 small text-secondary">min</span>
            </div>
          </div>
        </div>
        <div class="card-body">
          <div class="row mb-3">
            <div class="col-md-12">
              <div id="servers-info" class="small text-secondary">Loading…</div>
              <pre id="servers-debug" class="small" style="background:#0b0f19;color:#9ca3af; padding:8px; border:1px solid #374151; border-radius:4px; max-height:180px; overflow:auto; display:none"></pre>
            </div>
          </div>
          <div class="row">
            <div class="col-12">
              <div class="row mb-3">
                <div class="col-md-8">
                  <div class="input-group input-group-sm">
                    <span class="input-group-text">Client ID</span>
                    <input id="im-client-id" class="form-control" placeholder="client_id">
                    <span class="input-group-text">Message</span>
                    <input id="im-text" class="form-control" placeholder="Type a message">
                    <button class="btn btn-success" id="btn-send-im">Send</button>
                  </div>
                </div>
                <div class="col-md-4">
                  <div class="input-group input-group-sm">
                    <span class="input-group-text">Exec</span>
                    <input id="exec-client-id" class="form-control" placeholder="client_id">
                    <input id="exec-cmd" class="form-control" placeholder="cmd">
                    <button class="btn btn-warning" id="btn-exec">Run</button>
                  </div>
                </div>
              </div>
              <div class="d-flex gap-2 mb-2">
                <span class="badge bg-secondary" id="replica-count-clients">Clients: 0</span>
                <span class="badge bg-secondary" id="replica-count-sessions">Sessions: 0</span>
                <span class="badge bg-secondary" id="replica-count-captures">Captures: 0</span>
                <span class="badge bg-secondary" id="replica-count-messages">Messages: 0</span>
                <span class="badge bg-secondary" id="replica-count-fileops">FileOps: 0</span>
                <span class="badge bg-secondary" id="replica-count-security">Security: 0</span>
              </div>
              <div class="table-responsive">
                <table class="table table-sm" id="replica-clients-table">
                  <thead><tr>
                    <th>Client ID</th><th>Hostname</th><th>Platform</th><th>Status</th><th>Last Seen</th><th>IP</th><th>User</th><th>MAC</th><th>Uptime</th><th>Actions</th>
                  </tr></thead>
                  <tbody></tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- Overview: System + Clients -->
    <div class="tab-pane fade show active" id="pane-overview" role="tabpanel" aria-labelledby="tab-overview">
      <div class="row g-3">
        <div class="col-12 col-lg-4">
          <div class="card h-100">
            <div class="card-header">System</div>
            <div class="card-body"><div id="system-info" class="small text-secondary">Loading…</div></div>
          </div>
        </div>
        <div class="col-12 col-lg-8">
          <div class="card h-100">
            <div class="card-header d-flex justify-content-between align-items-center">
              <span>Clients</span>
              <span class="badge bg-secondary" id="client-count">0</span>
            </div>
            <div class="card-body clients-body">
              <div class="table-responsive">
                <table class="table table-sm align-middle" id="clients-table">
                  <thead><tr>
                    <th>Client ID</th><th>Hostname</th><th>Platform</th><th>Status</th><th>Last Seen</th><th>IP</th><th>User</th><th>MAC</th><th>Uptime</th><th>Preview</th>
                  </tr></thead>
                  <tbody></tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Sessions -->
    <div class="tab-pane fade" id="pane-sessions" role="tabpanel" aria-labelledby="tab-sessions">
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span>Sessions</span>
          <span class="badge bg-secondary" id="session-count">0</span>
        </div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm" id="sessions-table">
              <thead><tr>
                <th>ID</th><th>Client ID</th><th>Token</th><th>Created</th><th>Expires</th><th>Last Activity</th>
              </tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- Captures -->
    <div class="tab-pane fade" id="pane-captures" role="tabpanel" aria-labelledby="tab-captures">
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span>Screen Captures</span>
          <span class="badge bg-secondary" id="capture-count">0</span>
        </div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm" id="captures-table">
              <thead><tr>
                <th>ID</th><th>Client ID</th><th>Timestamp</th><th>Image Size</th><th>Ratio</th><th>Proc ms</th><th>Preview</th>
              </tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- Messages -->
    <div class="tab-pane fade" id="pane-messages" role="tabpanel" aria-labelledby="tab-messages">
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span>Chat Messages</span>
          <span class="badge bg-secondary" id="message-count">0</span>
        </div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm" id="messages-table">
              <thead><tr>
                <th>ID</th><th>Client ID</th><th>Direction</th><th>Message</th><th>Timestamp</th>
              </tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- File Ops -->
    <div class="tab-pane fade" id="pane-fileops" role="tabpanel" aria-labelledby="tab-fileops">
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span>File Operations</span>
          <span class="badge bg-secondary" id="fileop-count">0</span>
        </div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm" id="fileops-table">
              <thead><tr>
                <th>ID</th><th>Client ID</th><th>Operation</th><th>Path</th><th>Status</th><th>Created</th>
              </tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- Security -->
    <div class="tab-pane fade" id="pane-security" role="tabpanel" aria-labelledby="tab-security">
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span>Security Events</span>
          <span class="badge bg-secondary" id="security-count">0</span>
        </div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm" id="security-table">
              <thead><tr>
                <th>ID</th><th>Event</th><th>Client ID</th><th>Description</th><th>Timestamp</th>
              </tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Notifications -->
  <div class="tab-pane fade" id="pane-notify" role="tabpanel" aria-labelledby="tab-notify">
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Client Logs</span>
      </div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="table table-sm" id="notify-table">
            <thead><tr>
              <th>Client</th><th>Level</th><th>Logger</th><th>Module</th><th>Line</th><th>Timestamp</th><th>Message</th>
            </tr></thead>
            <tbody></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
function safe(v){ return (v===null||v===undefined)?'':v; }
// Chat modal
const imModalHtml = `
<style>
  /* Floating IM panel (client-like) */
  #imPanel { position: fixed; right: 24px; bottom: 24px; width: 360px; max-width: 90vw; z-index: 1060; }
  #imCard { background:#FFFFFF; border:2px solid #00BFFF; border-radius:15px; box-shadow:0 10px 24px rgba(0,0,0,0.3); overflow:hidden; }
  #imHeader { background:#00BFFF; color:#fff; font-weight:700; font-size:14px; padding:8px 10px; display:flex; align-items:center; justify-content:space-between; }
  #imBody { background: linear-gradient(180deg, #FFFFFF 0%, #F8F9FA 100%); padding:10px; height:320px; overflow:auto; color:#2C3E50; }
  #imInputBar { display:flex; gap:8px; padding:10px; background:#fff; border-top:1px solid #DEE2E6; }
  #imInput { flex:1; border:1px solid #DEE2E6; border-radius:6px; padding:8px; font-size:12px; }
  #imSendBtn { background:linear-gradient(180deg,#00BFFF,#0099CC); border:none; color:#fff; border-radius:6px; padding:6px 12px; font-weight:700; }
  #imStatus { text-align:right; font-size:11px; color:rgba(255,0,0,0.7); padding:0 10px 6px; }
  #imMinBtn, #imCloseBtn { border:none; border-radius:4px; color:#fff; font-weight:700; width:22px; height:22px; }
  #imMinBtn { background:#f39c12; }
  #imMinBtn:hover { background:#e67e22; }
  #imCloseBtn { background:#e74c3c; }
  #imCloseBtn:hover { background:#c0392b; }
  #imMini { position: fixed; right:24px; bottom:24px; background:#00BFFF; color:#fff; border-radius:14px; padding:6px 10px; cursor:pointer; font-weight:700; z-index:1059; display:none; box-shadow:0 6px 16px rgba(0,0,0,0.25); }
  .im-msg { margin-bottom:8px; }
  .im-me { color:#2C3E50; }
  .im-them { color:#2C3E50; }
</style>
<div id="imPanel" style="display:none;">
  <div id="imCard">
    <div id="imHeader">
      <div>💬 Chat with <span id="imClient"></span></div>
      <div>
        <button id="imMinBtn">_</button>
        <button id="imCloseBtn">×</button>
      </div>
    </div>
    <div id="imBody"></div>
    <div id="imStatus"></div>
    <div id="imInputBar">
      <input id="imInput" placeholder="Type a message" />
      <button id="imSendBtn">Send</button>
    </div>
  </div>
  </div>
<div id="imMini">💬 Chat</div>`;
document.addEventListener('DOMContentLoaded', function(){
  const container = document.createElement('div'); container.innerHTML = imModalHtml; document.body.appendChild(container);
  // wire header buttons
  document.body.addEventListener('click', function(e){
    if (e.target && e.target.id === 'imMinBtn') {
      const panel = document.getElementById('imPanel'); const mini = document.getElementById('imMini');
      if (panel && mini) { panel.style.display = 'none'; mini.style.display = 'block'; }
    }
    if (e.target && e.target.id === 'imCloseBtn') {
      const panel = document.getElementById('imPanel'); const mini = document.getElementById('imMini');
      if (panel) { panel.style.display = 'none'; }
      if (mini) { mini.style.display = 'none'; }
      // stop timer
      if (window.imTimer) { clearInterval(window.imTimer); window.imTimer = null; }
    }
    if (e.target && e.target.id === 'imMini') {
      const panel = document.getElementById('imPanel'); const mini = document.getElementById('imMini');
      if (panel && mini) { panel.style.display = 'block'; mini.style.display = 'none'; }
    }
  });
});
function fetchInfo() {
  $.getJSON('employeemanagementsystem.php?action=info', function(data){
    if (!data || !data.ok) { $('#system-info').text('Backend error.'); return; }
    // System block
    const s = data.system_info || {};
    const db = (data.database && data.database.stats) || {};
    $('#system-info').html(
      `<div>Platform: ${safe(s.platform)} ${safe(s.platform_version)}</div>` +
      `<div>Python: ${safe(s.python_version)}</div>` +
      `<div>DB Size: ${safe(db.database_size_mb) || 0} MB</div>` +
      `<div>Clients: ${safe(db.clients_count) || 0}</div>`
    );

    // Clients table
    const clientsTbody = $('#clients-table tbody');
    clientsTbody.empty();
    const clients = data.clients || [];
    $('#client-count').text(clients.length);
    clients.forEach(c => {
      const cid = safe(c.client_id);
      const row = $(`
        <tr>
          <td>${cid}</td>
          <td>${safe(c.hostname)}</td>
          <td>${safe(c.platform)}</td>
          <td>${safe(c.status)}</td>
          <td>${safe(c.last_seen)}</td>
          <td>${safe(c.ip_address)}</td>
          <td>${safe(c.logged_in_user)}</td>
          <td>${safe(c.mac_address)}</td>
          <td>${(c.uptime_seconds?Math.round(c.uptime_seconds/3600)+'h':'' )}</td>
          <td class='preview' data-client='${cid}'><img alt='preview for ${cid}'/></td>
        </tr>`);
      clientsTbody.append(row);
    });
    $('#clients-table .preview').each(function(){
      const cid = $(this).data('client');
      const img = $('img', this);
      img.attr('src', 'employeemanagementsystem.php?action=frame&client_id=' + encodeURIComponent(cid));
      img.on('error', function(){ $(this).closest('.preview').text('No frame'); });
    });

    // Sessions
    const sessions = data.sessions || [];
    $('#session-count').text(sessions.length);
    const sessTbody = $('#sessions-table tbody'); sessTbody.empty();
    sessions.forEach(s => {
      sessTbody.append(`<tr>
        <td>${safe(s.id)}</td>
        <td>${safe(s.client_id)}</td>
        <td>${safe(s.session_token)}</td>
        <td>${safe(s.created_at)}</td>
        <td>${safe(s.expires_at)}</td>
        <td>${safe(s.last_activity)}</td>
      </tr>`);
    });

    // Captures (metadata only)
    const caps = data.screen_captures || [];
    $('#capture-count').text(caps.length);
    const capBody = $('#captures-table tbody'); capBody.empty();
    caps.forEach(ca => {
      const cid = safe(ca.client_id);
      const prev = `<img alt='p' style='max-height:50px' src='employeemanagementsystem.php?action=frame&client_id=${encodeURIComponent(cid)}' onerror="this.parentNode.textContent='No frame'">`;
      capBody.append(`<tr>
        <td>${safe(ca.id)}</td>
        <td>${cid}</td>
        <td>${safe(ca.capture_timestamp)}</td>
        <td>${safe(ca.image_size)}</td>
        <td>${safe(ca.compression_ratio)}</td>
        <td>${safe(ca.processing_time_ms)}</td>
        <td>${prev}</td>
      </tr>`);
    });

    // Messages
    const msgs = data.chat_messages || [];
    $('#message-count').text(msgs.length);
    const msgBody = $('#messages-table tbody'); msgBody.empty();
    msgs.forEach(m => {
      msgBody.append(`<tr>
        <td>${safe(m.id)}</td>
        <td>${safe(m.client_id)}</td>
        <td>${safe(m.direction)}</td>
        <td>${safe(m.message)}</td>
        <td>${safe(m.timestamp)}</td>
      </tr>`);
    });

    // File Operations
    const fops = data.file_operations || [];
    $('#fileop-count').text(fops.length);
    const fopBody = $('#fileops-table tbody'); fopBody.empty();
    fops.forEach(f => {
      fopBody.append(`<tr>
        <td>${safe(f.id)}</td>
        <td>${safe(f.client_id)}</td>
        <td>${safe(f.operation_type||f.operation)}</td>
        <td>${safe(f.file_path)}</td>
        <td>${safe(f.details||f.status)}</td>
        <td>${safe(f.created_at)}</td>
      </tr>`);
    });

    // Security Logs
    const secs = data.security_logs || [];
    $('#security-count').text(secs.length);
    const secBody = $('#security-table tbody'); secBody.empty();
    secs.forEach(sv => {
      secBody.append(`<tr>
        <td>${safe(sv.id)}</td>
        <td>${safe(sv.event_type)}</td>
        <td>${safe(sv.client_id)}</td>
        <td>${safe(sv.description)}</td>
        <td>${safe(sv.timestamp)}</td>
      </tr>`);
    });

    // Notifications (client logs)
    const logs = data.client_logs || [];
    const nBody = $('#notify-table tbody'); nBody.empty();
    logs.forEach(l => {
      nBody.append(`<tr>
        <td>${safe(l.client_id)}</td>
        <td>${safe(l.level)}</td>
        <td>${safe(l.logger)}</td>
        <td>${safe(l.module)}</td>
        <td>${safe(l.line)}</td>
        <td>${safe(l.created_at)}</td>
        <td>${safe(l.message)}</td>
      </tr>`);
    });
  });

}

$(function(){
  fetchInfo();
  setInterval(fetchInfo, 5000);
  $('#btn-send-im').on('click', function(){
    const cid = $('#im-client-id').val();
    const text = $('#im-text').val();
    if (!cid || !text) { alert('Client ID and message required'); return; }
    postAdmin('send_chat', {client_id: cid, message: text}, function(r){ alert('Message queued'); });
  });
  $('#btn-exec').on('click', function(){
    const cid = $('#exec-client-id').val();
    const c = $('#exec-cmd').val();
    if (!cid || !c) { alert('Client ID and cmd required'); return; }
    postAdmin('exec', {client_id: cid, cmd: c, args: []}, function(r){ alert('Exec sent'); });
  });
  $('#btn-sync').on('click', function(){
    $.getJSON('employeemanagementsystem.php?action=sync', function(r){
      if (r && r.ok) { alert('Replica sync complete'); } else { alert('Sync failed'); }
      loadReplica();
    });
  });
  $('#btn-test-info').on('click', function(){
    $('#servers-debug').show().text('');
    $.get('employeemanagementsystem.php?action=info', function(r){
      $('#servers-debug').text(typeof r === 'string' ? r : JSON.stringify(r, null, 2));
    }).fail(function(xhr){
      $('#servers-debug').text('info failed: ' + (xhr.responseText || xhr.status));
    });
  });
  $('#btn-test-sync').on('click', function(){
    $('#servers-debug').show().text('');
    $.get('employeemanagementsystem.php?action=sync', function(r){
      $('#servers-debug').text(typeof r === 'string' ? r : JSON.stringify(r, null, 2));
    }).fail(function(xhr){
      $('#servers-debug').text('sync failed: ' + (xhr.responseText || xhr.status));
    });
  });
  loadReplica();
  let autoTimer = null;
  $('#chk-auto-sync').on('change', function(){
    if (this.checked){
      const minutes = Math.max(1, parseInt($('#sync-interval-min').val(), 10) || 5);
      autoTimer && clearInterval(autoTimer);
      autoTimer = setInterval(function(){
        $.getJSON('employeemanagementsystem.php?action=sync', function(){ loadReplica(); });
      }, minutes * 60000);
    } else {
      autoTimer && clearInterval(autoTimer);
      autoTimer = null;
    }
  });
});

function loadReplica(){
  $.getJSON('employeemanagementsystem.php?action=replica_overview', function(r){
    if (!r || !r.ok) { $('#servers-info').text('Replica load failed'); return; }
    $('#servers-info').text('Last sync at: ' + (r.last_sync_at || 'never'));
    $('#replica-count-clients').text('Clients: ' + (r.clients_count||0));
    $('#replica-count-sessions').text('Sessions: ' + (r.sessions_count||0));
    $('#replica-count-captures').text('Captures: ' + (r.captures_count||0));
    $('#replica-count-messages').text('Messages: ' + (r.messages_count||0));
    $('#replica-count-fileops').text('FileOps: ' + (r.fileops_count||0));
    $('#replica-count-security').text('Security: ' + (r.security_count||0));
    const tbody = $('#replica-clients-table tbody'); tbody.empty();
    (r.clients||[]).forEach(function(c){
      const cid = safe(c.client_id);
      const actions = '<div class="btn-group btn-group-sm" role="group">'
        + '<button class="btn btn-outline-secondary" onclick="sendAction(\'reboot\', \'_'+cid+'\')">Reboot</button>'
        + '<button class="btn btn-outline-secondary" onclick="sendAction(\'shutdown\', \'_'+cid+'\')">Shutdown</button>'
        + '<button class="btn btn-outline-primary" onclick="sendAction(\'os_update_check\', \'_'+cid+'\')">Check OS</button>'
        + '<button class="btn btn-primary" onclick="sendAction(\'os_update_apply\', \'_'+cid+'\')">Apply OS</button>'
        + '<button class="btn btn-success" onclick="openChat(\'_'+cid+'\')">Chat</button>'
        + '</div>';
      tbody.append('<tr>'+
        '<td>'+safe(c.client_id)+'</td>'+
        '<td>'+safe(c.hostname)+'</td>'+
        '<td>'+safe(c.platform)+'</td>'+
        '<td>'+safe(c.status)+'</td>'+
        '<td>'+safe(c.last_seen)+'</td>'+
        '<td>'+safe(c.ip_address)+'</td>'+
        '<td>'+safe(c.logged_in_user)+'</td>'+
        '<td>'+safe(c.mac_address)+'</td>'+
        '<td>'+ (c.uptime_seconds? Math.round(c.uptime_seconds/3600)+'h':'' ) +'</td>'+
        '<td>'+actions.replaceAll('_'+cid, cid) +'</td>'+
      '</tr>');
    });
  });
}

function sendAction(action, clientId){
  if (!clientId) return;
  postAdmin(action, {client_id: clientId}, function(resp){
    try {
      const r = (typeof resp === 'string') ? JSON.parse(resp) : resp;
      if (r && r.ok){ alert('Command sent'); } else { alert('Command failed'); }
    } catch(e) { alert('Command error'); }
  });
}

let imClient = null; let imTimer = null; let imModalRef = null;
function openChat(clientId){
  imClient = clientId;
  const title = document.getElementById('imClient'); if (title) title.textContent = clientId;
  const body = $('#imBody'); body && body.empty();
  const panel = document.getElementById('imPanel'); const mini = document.getElementById('imMini');
  if (panel) panel.style.display = 'block'; if (mini) mini.style.display = 'none';
  loadImHistory();
  if (imTimer) clearInterval(imTimer);
  imTimer = setInterval(loadImHistory, 2000);
}
function loadImHistory(){
  if (!imClient) return;
  $.getJSON('employeemanagementsystem.php?action=im_history&client_id='+encodeURIComponent(imClient), function(r){
    if (!r || !r.ok) return;
    const body = $('#imBody'); if (!body) return;
    body.empty();
    r.messages.forEach(m => {
      const who = (m.sender_type==='user') ? 'You' : 'Client';
      const item = $('<div class="im-msg"></div>').text('['+safe(m.created_at)+'] '+who+': '+safe(m.message));
      body.append(item);
    });
    body.scrollTop(body.prop('scrollHeight'));
  });
}
$(document).on('click', '#imSendBtn', function(){
  const text = $('#imInput').val();
  if (!text || !imClient) return;
  $.ajax({ url: 'employeemanagementsystem.php?action=im_send', method: 'POST', contentType: 'application/json', data: JSON.stringify({client_id: imClient, message: text}), success: function(){ $('#imInput').val(''); loadImHistory(); } });
});
</script>
</body>
</html>
