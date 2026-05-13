<?php
/**
 * Single-file directory browser and file manager for local/Laragon-style stacks.
 * Mutations (upload, delete, rename, move) require authentication.
 */
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$ROOT = realpath(__DIR__);
if ($ROOT === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Cannot resolve document root.';
    exit;
}

const SETTINGS_FILE = '.fm_settings.json';
const MAX_PREVIEW_BYTES = 2_097_152; // 2 MiB
const CSRF_KEY = 'fm_csrf';

function fm_os_is_windows(): bool
{
    return defined('PHP_OS_FAMILY') ? PHP_OS_FAMILY === 'Windows' : stripos(PHP_OS, 'WIN') === 0;
}

function fm_normalize_path(string $path): string
{
    return str_replace('\\', '/', $path);
}

function fm_starts_with(string $haystack, string $needle): bool
{
    return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
}

function fm_path_under_root(string $root, string $candidate): bool
{
    $rootReal = realpath($root);
    if ($rootReal === false) {
        return false;
    }
    $rootNorm = rtrim(fm_normalize_path($rootReal), '/');

    $cReal = realpath($candidate);
    if ($cReal !== false) {
        $cNorm = rtrim(fm_normalize_path($cReal), '/');
    } else {
        $parent = realpath(dirname($candidate));
        if ($parent === false) {
            return false;
        }
        $cNorm = rtrim(fm_normalize_path($parent), '/') . '/' . basename($candidate);
    }

    if (fm_os_is_windows()) {
        $rootNorm = strtolower($rootNorm);
        $cNorm = strtolower($cNorm);
    }

    if ($cNorm === $rootNorm) {
        return true;
    }

    return strncmp($cNorm . '/', $rootNorm . '/', strlen($rootNorm) + 1) === 0;
}

function fm_relative_from_root(string $root, string $absolute): string
{
    $r = realpath($root);
    if ($r === false) {
        return '';
    }
    $a = realpath($absolute);
    if ($a === false) {
        $dir = realpath(dirname($absolute));
        if ($dir === false) {
            return '';
        }
        $a = $dir . DIRECTORY_SEPARATOR . basename($absolute);
    }
    $rN = rtrim(fm_normalize_path($r), '/');
    $aN = rtrim(fm_normalize_path($a), '/');
    if (fm_os_is_windows()) {
        if (strcasecmp($rN, $aN) === 0) {
            return '';
        }
        $prefix = $rN . '/';
        if (strlen($aN) < strlen($prefix) || strncasecmp($aN, $prefix, strlen($prefix)) !== 0) {
            return '';
        }
        return substr($aN, strlen($prefix));
    }
    if ($aN === $rN) {
        return '';
    }
    $prefix = $rN . '/';
    if (strlen($aN) < strlen($prefix) || strncmp($aN, $prefix, strlen($prefix)) !== 0) {
        return '';
    }
    return substr($aN, strlen($prefix));
}

function fm_safe_join(string $root, string $rel): ?string
{
    $rel = str_replace("\0", '', $rel);
    $rel = str_replace('\\', '/', $rel);
    $rel = trim($rel, '/');
    $parts = $rel === '' ? [] : explode('/', $rel);
    $acc = $root;
    foreach ($parts as $p) {
        if ($p === '' || $p === '.') {
            continue;
        }
        if ($p === '..') {
            return null;
        }
        $acc .= DIRECTORY_SEPARATOR . $p;
    }
    if (!fm_path_under_root($root, $acc)) {
        return null;
    }
    return $acc;
}

function fm_load_settings(): array
{
    $f = __DIR__ . DIRECTORY_SEPARATOR . SETTINGS_FILE;
    if (!is_readable($f)) {
        return [];
    }
    $j = json_decode((string) file_get_contents($f), true);
    return is_array($j) ? $j : [];
}

function fm_save_password_hash(string $hash): void
{
    $f = __DIR__ . DIRECTORY_SEPARATOR . SETTINGS_FILE;
    $data = fm_load_settings();
    $data['password_hash'] = $hash;
    file_put_contents($f, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function fm_verify_credentials(string $user, string $pass): bool
{
    if ($user !== 'admin') {
        return false;
    }
    $settings = fm_load_settings();
    if (!empty($settings['password_hash']) && is_string($settings['password_hash'])) {
        return password_verify($pass, $settings['password_hash']);
    }
    // First run: default admin / admin, then persist hash.
    if ($pass === 'admin') {
        fm_save_password_hash(password_hash('admin', PASSWORD_DEFAULT));
        return true;
    }
    return false;
}

function fm_is_authenticated(): bool
{
    return !empty($_SESSION['fm_auth']) && $_SESSION['fm_auth'] === true;
}

function fm_csrf_token(): string
{
    if (empty($_SESSION[CSRF_KEY]) || !is_string($_SESSION[CSRF_KEY])) {
        $_SESSION[CSRF_KEY] = bin2hex(random_bytes(32));
    }
    return $_SESSION[CSRF_KEY];
}

function fm_csrf_validate(?string $token): bool
{
    return is_string($token) && isset($_SESSION[CSRF_KEY]) && hash_equals($_SESSION[CSRF_KEY], $token);
}

function fm_json_response(array $payload, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fm_dir_size(string $dir): int
{
    $size = 0;
    if (!is_dir($dir) || !is_readable($dir)) {
        return 0;
    }
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS)
        );
        foreach ($it as $file) {
            if ($file->isFile()) {
                $size += (int) $file->getSize();
            }
        }
    } catch (Throwable $e) {
        // ignore unreadable entries
    }
    return $size;
}

function fm_format_bytes(int $bytes): string
{
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    $v = (float) $bytes;
    while ($v >= 1024 && $i < count($u) - 1) {
        $v /= 1024;
        $i++;
    }
    return ($i === 0 ? (string) $bytes : number_format($v, $i > 2 ? 2 : 1)) . ' ' . $u[$i];
}

function fm_extension(string $name): string
{
    $p = strrpos($name, '.');
    return $p === false ? '' : strtolower(substr($name, $p + 1));
}

function fm_icon_for_name(string $name, bool $isDir): string
{
    if ($isDir) {
        return '📁';
    }
    $ext = fm_extension($name);
    $map = [
        'php' => '🐘', 'phtml' => '🐘', 'html' => '🌐', 'htm' => '🌐', 'css' => '🎨', 'js' => '📜', 'mjs' => '📜',
        'json' => '📋', 'xml' => '📄', 'yml' => '⚙️', 'yaml' => '⚙️', 'ini' => '⚙️', 'env' => '⚙️',
        'md' => '📝', 'txt' => '📝', 'log' => '📋',
        'jpg' => '🖼️', 'jpeg' => '🖼️', 'png' => '🖼️', 'gif' => '🖼️', 'webp' => '🖼️', 'svg' => '🖼️', 'ico' => '🖼️',
        'pdf' => '📕', 'zip' => '📦', 'rar' => '📦', '7z' => '📦', 'tar' => '📦', 'gz' => '📦',
        'mp3' => '🎵', 'wav' => '🎵', 'flac' => '🎵', 'mp4' => '🎬', 'webm' => '🎬', 'mkv' => '🎬',
        'csv' => '📊', 'xlsx' => '📊', 'xls' => '📊', 'sql' => '🗄️', 'sqlite' => '🗄️', 'db' => '🗄️',
        'py' => '🐍', 'rb' => '💎', 'go' => '🔷', 'rs' => '🦀', 'java' => '☕', 'c' => '©️', 'cpp' => '©️', 'h' => '©️',
    ];
    return $map[$ext] ?? '📄';
}

function fm_preview_kind(string $path): string
{
    if (is_dir($path)) {
        return 'dir';
    }
    $ext = fm_extension(basename($path));
    $mime = 'application/octet-stream';
    if (is_file($path) && function_exists('mime_content_type')) {
        $detected = @mime_content_type($path);
        if (is_string($detected) && $detected !== '') {
            $mime = $detected;
        }
    }
    if (fm_starts_with($mime, 'image/')) {
        return 'image';
    }
    if ($mime === 'application/pdf' || $ext === 'pdf') {
        return 'pdf';
    }
    $textLike = ['txt', 'log', 'md', 'csv', 'json', 'xml', 'yml', 'yaml', 'ini', 'env', 'sh', 'bat', 'sql', 'htm', 'html', 'css', 'js', 'php', 'ts', 'tsx', 'jsx', 'vue', 'c', 'h', 'cpp', 'py', 'rb', 'go', 'rs', 'java'];
    if (in_array($ext, $textLike, true) || fm_starts_with($mime, 'text/') || $ext === 'csv') {
        return 'text';
    }
    return 'binary';
}

// --- API (JSON) ---
if (isset($_GET['api'])) {
    header('X-Content-Type-Options: nosniff');
    $api = (string) $_GET['api'];
    $rel = isset($_GET['path']) ? (string) $_GET['path'] : '';
    $abs = fm_safe_join($ROOT, $rel);
    if ($abs === null) {
        fm_json_response(['ok' => false, 'error' => 'Invalid path'], 400);
    }

    if ($api === 'hashes') {
        if (!fm_is_authenticated()) {
            fm_json_response(['ok' => false, 'error' => 'Authentication required'], 401);
        }
        if (!is_file($abs)) {
            fm_json_response(['ok' => false, 'error' => 'Not a file'], 400);
        }
        if (filesize($abs) > 100 * 1024 * 1024) {
            fm_json_response(['ok' => false, 'error' => 'File too large for hashing in-browser tool'], 413);
        }
        fm_json_response([
            'ok' => true,
            'md5' => md5_file($abs),
            'sha1' => sha1_file($abs),
            'sha256' => hash_file('sha256', $abs),
        ]);
    }

    if ($api === 'dirsize') {
        if (!is_dir($abs)) {
            fm_json_response(['ok' => false, 'error' => 'Not a directory'], 400);
        }
        $bytes = fm_dir_size($abs);
        fm_json_response(['ok' => true, 'bytes' => $bytes, 'formatted' => fm_format_bytes($bytes)]);
    }

    if ($api === 'serverinfo') {
        $free = @disk_free_space($ROOT);
        fm_json_response([
            'ok' => true,
            'php_version' => PHP_VERSION,
            'zip_loaded' => extension_loaded('zip'),
            'disk_free_bytes' => $free !== false ? (int) $free : null,
            'disk_free_formatted' => $free !== false ? fm_format_bytes((int) $free) : null,
            'document_root' => $ROOT,
        ]);
    }

    fm_json_response(['ok' => false, 'error' => 'Unknown API'], 404);
}

// --- Download ---
if (isset($_GET['download'])) {
    $rel = (string) $_GET['download'];
    $abs = fm_safe_join($ROOT, $rel);
    if ($abs === null || !is_file($abs)) {
        http_response_code(404);
        exit;
    }
    $name = basename($abs);
    header('X-Content-Type-Options: nosniff');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . str_replace('"', '', $name) . '"');
    header('Content-Length: ' . (string) filesize($abs));
    readfile($abs);
    exit;
}

// --- Preview (iframe / raw) ---
if (isset($_GET['preview'])) {
    $rel = (string) $_GET['preview'];
    $abs = fm_safe_join($ROOT, $rel);
    if ($abs === null || !is_readable($abs) || is_dir($abs)) {
        http_response_code(404);
        echo 'Not found';
        exit;
    }
    $kind = fm_preview_kind($abs);
    header('X-Content-Type-Options: nosniff');
    if ($kind === 'image') {
        $ext = fm_extension(basename($abs));
        $types = ['png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'webp' => 'image/webp', 'svg' => 'image/svg+xml', 'ico' => 'image/x-icon'];
        header('Content-Type: ' . ($types[$ext] ?? 'application/octet-stream'));
        readfile($abs);
        exit;
    }
    if ($kind === 'pdf') {
        header('Content-Type: application/pdf');
        header('Content-Disposition: inline; filename="' . str_replace('"', '', basename($abs)) . '"');
        readfile($abs);
        exit;
    }
    if ($kind === 'text') {
        $size = filesize($abs);
        if ($size !== false && $size > MAX_PREVIEW_BYTES) {
            http_response_code(413);
            header('Content-Type: text/plain; charset=UTF-8');
            echo 'Preview limited to ' . MAX_PREVIEW_BYTES . ' bytes. Download the file instead.';
            exit;
        }
        $body = (string) file_get_contents($abs);
        header('Content-Type: text/plain; charset=UTF-8');
        echo $body;
        exit;
    }
    http_response_code(415);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'No inline preview for this type.';
    exit;
}

// --- POST actions ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = isset($_POST['action']) ? (string) $_POST['action'] : '';

    if ($action === 'login') {
        $u = isset($_POST['username']) ? (string) $_POST['username'] : '';
        $p = isset($_POST['password']) ? (string) $_POST['password'] : '';
        if (fm_verify_credentials($u, $p)) {
            $_SESSION['fm_auth'] = true;
            $_SESSION['fm_user'] = $u;
        }
        header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'index.php', '?'));
        exit;
    }

    if ($action === 'logout') {
        if (!fm_csrf_validate($_POST['csrf'] ?? null)) {
            http_response_code(403);
            exit('Invalid CSRF');
        }
        $_SESSION['fm_auth'] = false;
        unset($_SESSION['fm_user']);
        header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'index.php', '?'));
        exit;
    }

    $needAuth = in_array($action, ['upload', 'delete', 'rename', 'move'], true);
    if ($needAuth && !fm_is_authenticated()) {
        http_response_code(403);
        exit('Authentication required');
    }
    if ($needAuth && !fm_csrf_validate($_POST['csrf'] ?? null)) {
        http_response_code(403);
        exit('Invalid CSRF');
    }

    if ($action === 'upload') {
        $targetRel = isset($_POST['target']) ? (string) $_POST['target'] : '';
        $destDir = fm_safe_join($ROOT, $targetRel);
        if ($destDir === null || !is_dir($destDir) || !is_writable($destDir)) {
            http_response_code(400);
            exit('Invalid upload directory');
        }
        if (empty($_FILES['file']['name']) || !isset($_FILES['file']['tmp_name'])) {
            http_response_code(400);
            exit('No file');
        }
        $orig = basename((string) $_FILES['file']['name']);
        $orig = str_replace(["\0", '/', '\\'], '', $orig);
        $targetPath = $destDir . DIRECTORY_SEPARATOR . $orig;
        if (!fm_path_under_root($ROOT, $targetPath)) {
            http_response_code(400);
            exit('Invalid path');
        }
        if (!move_uploaded_file((string) $_FILES['file']['tmp_name'], $targetPath)) {
            http_response_code(500);
            exit('Upload failed');
        }
        header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'index.php', '?') . '?dir=' . rawurlencode($targetRel));
        exit;
    }

    if ($action === 'delete') {
        $rel = isset($_POST['path']) ? (string) $_POST['path'] : '';
        $abs = fm_safe_join($ROOT, $rel);
        if ($abs === null || $abs === $ROOT) {
            http_response_code(400);
            exit('Invalid delete target');
        }
        if (is_file($abs)) {
            @unlink($abs);
        } elseif (is_dir($abs)) {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($it as $f) {
                $p = $f->getPathname();
                $f->isDir() ? @rmdir($p) : @unlink($p);
            }
            @rmdir($abs);
        }
        $parent = dirname($rel);
        $q = $parent === '.' || $parent === '' ? '' : '?dir=' . rawurlencode(str_replace('\\', '/', $parent));
        header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'index.php', '?') . $q);
        exit;
    }

    if ($action === 'rename') {
        $rel = isset($_POST['path']) ? (string) $_POST['path'] : '';
        $newName = isset($_POST['new_name']) ? basename(str_replace(["\0", '/', '\\'], '', (string) $_POST['new_name'])) : '';
        $abs = fm_safe_join($ROOT, $rel);
        if ($abs === null || $newName === '' || $abs === $ROOT) {
            http_response_code(400);
            exit('Invalid rename');
        }
        $parent = dirname($abs);
        $target = $parent . DIRECTORY_SEPARATOR . $newName;
        if (!fm_path_under_root($ROOT, $target)) {
            http_response_code(400);
            exit('Invalid target');
        }
        if (!@rename($abs, $target)) {
            http_response_code(500);
            exit('Rename failed');
        }
        $newRel = fm_relative_from_root($ROOT, $target);
        $parent = str_replace('\\', '/', dirname($newRel));
        if ($parent === '.' || $parent === '') {
            $loc = strtok($_SERVER['REQUEST_URI'] ?? 'index.php', '?');
        } else {
            $loc = strtok($_SERVER['REQUEST_URI'] ?? 'index.php', '?') . '?dir=' . rawurlencode($parent);
        }
        header('Location: ' . $loc);
        exit;
    }

    if ($action === 'move') {
        $rel = isset($_POST['path']) ? (string) $_POST['path'] : '';
        $destRel = isset($_POST['dest_dir']) ? (string) $_POST['dest_dir'] : '';
        $abs = fm_safe_join($ROOT, $rel);
        $destDir = fm_safe_join($ROOT, $destRel);
        if ($abs === null || $destDir === null || !is_dir($destDir)) {
            http_response_code(400);
            exit('Invalid move');
        }
        $name = basename($abs);
        $target = $destDir . DIRECTORY_SEPARATOR . $name;
        if (!fm_path_under_root($ROOT, $target)) {
            http_response_code(400);
            exit('Invalid destination');
        }
        if (!@rename($abs, $target)) {
            http_response_code(500);
            exit('Move failed');
        }
        header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'index.php', '?') . '?dir=' . rawurlencode(str_replace('\\', '/', $destRel)));
        exit;
    }
}

// --- View state ---
$dirRel = isset($_GET['dir']) ? (string) $_GET['dir'] : '';
$dirAbs = fm_safe_join($ROOT, $dirRel);
if ($dirAbs === null || !is_dir($dirAbs)) {
    $dirRel = '';
    $dirAbs = $ROOT;
}

$entries = [];
if (is_readable($dirAbs)) {
    $dh = opendir($dirAbs);
    if ($dh !== false) {
        while (($name = readdir($dh)) !== false) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            if ($name === SETTINGS_FILE) {
                continue;
            }
            $full = $dirAbs . DIRECTORY_SEPARATOR . $name;
            $rel = ltrim($dirRel . '/' . $name, '/');
            $isDir = is_dir($full);
            $size = $isDir ? null : (is_file($full) ? filesize($full) : 0);
            $entries[] = [
                'name' => $name,
                'rel' => str_replace('\\', '/', $rel),
                'is_dir' => $isDir,
                'size' => $size,
                'mtime' => @filemtime($full) ?: 0,
            ];
        }
        closedir($dh);
    }
    usort($entries, static function ($a, $b) {
        if ($a['is_dir'] !== $b['is_dir']) {
            return $a['is_dir'] ? -1 : 1;
        }
        return strcasecmp($a['name'], $b['name']);
    });
}

$parentRel = '';
if ($dirRel !== '') {
    $normDir = str_replace('\\', '/', $dirRel);
    $pd = dirname($normDir);
    $parentRel = ($pd === '.' || $pd === '') ? '' : $pd;
}

$breadcrumbs = [];
$acc = '';
foreach ($dirRel === '' ? [] : explode('/', str_replace('\\', '/', $dirRel)) as $seg) {
    if ($seg === '') {
        continue;
    }
    $acc = ltrim($acc . '/' . $seg, '/');
    $breadcrumbs[] = ['name' => $seg, 'path' => $acc];
}

$csrf = fm_csrf_token();
$auth = fm_is_authenticated();
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>File manager</title>
    <style>
        :root {
            --bg: #f4f6fb;
            --surface: #ffffff;
            --text: #1a1d26;
            --muted: #5c647a;
            --border: #d8deeb;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --danger: #b91c1c;
            --radius: 10px;
            --shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
        }
        [data-theme="dark"] {
            --bg: #0f1117;
            --surface: #171a22;
            --text: #e8eaf0;
            --muted: #9aa3b5;
            --border: #2a3142;
            --accent: #60a5fa;
            --accent-hover: #93c5fd;
            --danger: #f87171;
            --shadow: 0 8px 28px rgba(0, 0, 0, 0.45);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; color: var(--accent-hover); }
        .wrap { max-width: 1200px; margin: 0 auto; padding: 1.25rem; }
        header.top {
            display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; justify-content: space-between;
            margin-bottom: 1rem;
        }
        .brand { font-weight: 700; font-size: 1.15rem; }
        .toolbar { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
        button, .btn {
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text);
            border-radius: 8px;
            padding: 0.45rem 0.75rem;
            font-size: 0.9rem;
            cursor: pointer;
        }
        button.primary, .btn.primary {
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }
        button.primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
        button.danger { border-color: var(--danger); color: var(--danger); background: transparent; }
        .panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .crumbs {
            display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem; font-size: 0.95rem;
            margin-bottom: 0.5rem;
        }
        .crumbs code {
            background: var(--bg); padding: 0.2rem 0.45rem; border-radius: 6px; border: 1px solid var(--border);
            font-size: 0.85rem; word-break: break-all;
        }
        table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
        th, td { padding: 0.55rem 0.4rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: middle; }
        th { color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
        tr:hover td { background: rgba(37, 99, 235, 0.04); }
        [data-theme="dark"] tr:hover td { background: rgba(96, 165, 250, 0.06); }
        .icon { width: 2rem; text-align: center; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.82rem; }
        .muted { color: var(--muted); font-size: 0.85rem; }
        .flex { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
        .grow { flex: 1; min-width: 140px; }
        input[type="text"], input[type="password"], select {
            width: 100%; max-width: 320px; padding: 0.45rem 0.55rem; border-radius: 8px;
            border: 1px solid var(--border); background: var(--bg); color: var(--text);
        }
        .modal-backdrop {
            position: fixed; inset: 0; background: rgba(15, 17, 23, 0.55); display: none;
            align-items: center; justify-content: center; z-index: 50; padding: 1rem;
        }
        .modal-backdrop.show { display: flex; }
        .modal {
            background: var(--surface); color: var(--text); border-radius: var(--radius);
            border: 1px solid var(--border); max-width: 960px; width: 100%; max-height: 90vh;
            overflow: auto; box-shadow: var(--shadow); padding: 1rem;
        }
        .modal h3 { margin-top: 0; }
        .preview-frame { width: 100%; min-height: 360px; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); }
        .preview-text { white-space: pre-wrap; word-break: break-word; max-height: 60vh; overflow: auto; }
        .hash-row span { display: inline-block; margin-right: 0.75rem; margin-bottom: 0.25rem; }
        .dl-progress-wrap {
            position: fixed; right: 1rem; bottom: 1rem; width: 280px; max-width: calc(100vw - 2rem);
            background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
            box-shadow: var(--shadow); padding: 0.75rem; display: none; z-index: 60;
        }
        .dl-progress-wrap.show { display: block; }
        .dl-bar { height: 8px; border-radius: 999px; background: var(--border); overflow: hidden; margin-top: 0.35rem; }
        .dl-bar > i { display: block; height: 100%; width: 0%; background: linear-gradient(90deg, var(--accent), #22c55e); transition: width 0.12s ease; }
        .server-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; }
        .kv { padding: 0.5rem 0.65rem; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); }
        .kv strong { display: block; font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
        .login-box { max-width: 360px; }
        .sr-hint { font-size: 0.8rem; color: var(--muted); margin-top: 0.35rem; }
    </style>
</head>
<body>
<div class="wrap">
    <header class="top">
        <div class="brand">Local file manager</div>
        <div class="toolbar">
            <button type="button" id="btn-theme" title="Toggle light/dark">Theme</button>
            <button type="button" id="btn-server" class="primary">Server info</button>
            <?php if ($auth): ?>
                <span class="muted">Signed in as <?php echo htmlspecialchars((string) ($_SESSION['fm_user'] ?? 'admin'), ENT_QUOTES, 'UTF-8'); ?></span>
                <form method="post" style="display:inline" onsubmit="return confirm('Sign out?');">
                    <input type="hidden" name="action" value="logout">
                    <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit">Sign out</button>
                </form>
            <?php else: ?>
                <button type="button" id="btn-login">Admin sign-in</button>
            <?php endif; ?>
        </div>
    </header>

    <div class="panel">
        <div class="crumbs">
            <a href="?">🏠 Root</a>
            <?php foreach ($breadcrumbs as $bc): ?>
                <span class="muted">/</span>
                <a href="?dir=<?php echo rawurlencode($bc['path']); ?>"><?php echo htmlspecialchars($bc['name'], ENT_QUOTES, 'UTF-8'); ?></a>
            <?php endforeach; ?>
        </div>
        <div class="flex" style="margin-bottom:0.75rem">
            <code class="mono grow" id="breadcrumb-path"><?php echo htmlspecialchars($dirRel === '' ? '/' : '/' . str_replace('\\', '/', $dirRel), ENT_QUOTES, 'UTF-8'); ?></code>
            <button type="button" id="btn-copy-crumb" class="primary">Copy path</button>
        </div>
        <?php if ($auth): ?>
            <form method="post" enctype="multipart/form-data" class="flex" style="margin-bottom:0.75rem">
                <input type="hidden" name="action" value="upload">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="target" value="<?php echo htmlspecialchars(str_replace('\\', '/', $dirRel), ENT_QUOTES, 'UTF-8'); ?>">
                <input type="file" name="file" required>
                <button type="submit" class="primary">Upload</button>
            </form>
        <?php else: ?>
            <p class="muted">Upload, delete, rename, and move require admin sign-in (default <code>admin</code> / <code>admin</code> on first run).</p>
        <?php endif; ?>
    </div>

    <div class="panel" style="overflow:auto">
        <table>
            <thead>
            <tr>
                <th class="icon"></th>
                <th>Name</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Actions</th>
            </tr>
            </thead>
            <tbody>
            <?php if ($dirRel !== ''): ?>
                <tr>
                    <td class="icon">📂</td>
                    <td colspan="4">
                        <a href="<?php echo $parentRel === '' ? '?' : '?dir=' . rawurlencode($parentRel); ?>">Parent directory</a>
                    </td>
                </tr>
            <?php endif; ?>
            <?php foreach ($entries as $e): ?>
                <tr data-rel="<?php echo htmlspecialchars($e['rel'], ENT_QUOTES, 'UTF-8'); ?>" data-is-dir="<?php echo $e['is_dir'] ? '1' : '0'; ?>">
                    <td class="icon"><?php echo fm_icon_for_name($e['name'], $e['is_dir']); ?></td>
                    <td>
                        <?php if ($e['is_dir']): ?>
                            <a href="?dir=<?php echo rawurlencode($e['rel']); ?>"><strong><?php echo htmlspecialchars($e['name'], ENT_QUOTES, 'UTF-8'); ?></strong></a>
                        <?php else: ?>
                            <span><?php echo htmlspecialchars($e['name'], ENT_QUOTES, 'UTF-8'); ?></span>
                        <?php endif; ?>
                    </td>
                    <td class="mono">
                        <?php if ($e['is_dir']): ?>
                            <span class="dir-size muted" data-path="<?php echo htmlspecialchars($e['rel'], ENT_QUOTES, 'UTF-8'); ?>">calculating…</span>
                        <?php else: ?>
                            <?php echo $e['size'] !== null ? htmlspecialchars(fm_format_bytes((int) $e['size']), ENT_QUOTES, 'UTF-8') : '—'; ?>
                        <?php endif; ?>
                    </td>
                    <td class="muted mono"><?php echo htmlspecialchars(date('Y-m-d H:i', (int) $e['mtime']), ENT_QUOTES, 'UTF-8'); ?></td>
                    <td>
                        <div class="flex">
                            <?php if (!$e['is_dir']): ?>
                                <button type="button" class="btn-preview" data-rel="<?php echo htmlspecialchars($e['rel'], ENT_QUOTES, 'UTF-8'); ?>">Preview</button>
                                <a class="dl-link" href="?download=<?php echo rawurlencode($e['rel']); ?>">Download</a>
                            <?php endif; ?>
                            <?php if ($auth): ?>
                                <?php if (!$e['is_dir']): ?>
                                    <button type="button" class="btn-hashes" data-rel="<?php echo htmlspecialchars($e['rel'], ENT_QUOTES, 'UTF-8'); ?>">Hashes</button>
                                <?php endif; ?>
                                <button type="button" class="btn-rename" data-rel="<?php echo htmlspecialchars($e['rel'], ENT_QUOTES, 'UTF-8'); ?>" data-name="<?php echo htmlspecialchars($e['name'], ENT_QUOTES, 'UTF-8'); ?>">Rename</button>
                                <button type="button" class="btn-move" data-rel="<?php echo htmlspecialchars($e['rel'], ENT_QUOTES, 'UTF-8'); ?>">Move</button>
                                <form method="post" style="display:inline" onsubmit="return confirm('Delete permanently?');">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($e['rel'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <button type="submit" class="danger">Delete</button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="modal-backdrop" id="modal-login" role="dialog" aria-modal="true">
    <div class="modal login-box">
        <h3>Admin sign-in</h3>
        <form method="post">
            <input type="hidden" name="action" value="login">
            <p><label>Username<br><input name="username" type="text" autocomplete="username" required></label></p>
            <p><label>Password<br><input name="password" type="password" autocomplete="current-password" required></label></p>
            <button type="submit" class="primary">Sign in</button>
            <button type="button" id="login-cancel">Cancel</button>
        </form>
        <p class="sr-hint">First sign-in with <code>admin</code> / <code>admin</code> stores a bcrypt hash in <code><?php echo htmlspecialchars(SETTINGS_FILE, ENT_QUOTES, 'UTF-8'); ?></code>. Change the password by replacing that file’s <code>password_hash</code> with a new hash from <code>password_hash('yourpass', PASSWORD_DEFAULT)</code> in PHP.</p>
    </div>
</div>

<div class="modal-backdrop" id="modal-preview" role="dialog" aria-modal="true">
    <div class="modal">
        <h3 id="preview-title">Preview</h3>
        <div id="preview-body"></div>
        <p class="flex" style="margin-top:0.75rem">
            <button type="button" id="preview-close" class="primary">Close</button>
        </p>
    </div>
</div>

<div class="modal-backdrop" id="modal-hashes" role="dialog" aria-modal="true">
    <div class="modal">
        <h3>File hashes</h3>
        <div id="hash-body" class="mono hash-row"></div>
        <button type="button" id="hash-close" class="primary" style="margin-top:0.75rem">Close</button>
    </div>
</div>

<div class="modal-backdrop" id="modal-rename" role="dialog" aria-modal="true">
    <div class="modal login-box">
        <h3>Rename</h3>
        <form method="post" id="form-rename">
            <input type="hidden" name="action" value="rename">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="path" id="rename-path">
            <p><label>New name<br><input type="text" name="new_name" id="rename-input" required></label></p>
            <button type="submit" class="primary">Save</button>
            <button type="button" id="rename-cancel">Cancel</button>
        </form>
    </div>
</div>

<div class="modal-backdrop" id="modal-move" role="dialog" aria-modal="true">
    <div class="modal login-box">
        <h3>Move to folder</h3>
        <form method="post" id="form-move">
            <input type="hidden" name="action" value="move">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="path" id="move-path">
            <p><label>Destination (relative to root)<br><input type="text" name="dest_dir" id="move-dest" placeholder="subdir/nested" required></label></p>
            <button type="submit" class="primary">Move</button>
            <button type="button" id="move-cancel">Cancel</button>
        </form>
    </div>
</div>

<div class="modal-backdrop" id="modal-server" role="dialog" aria-modal="true">
    <div class="modal">
        <h3>Server information</h3>
        <div class="server-grid" id="server-body"></div>
        <button type="button" id="server-close" class="primary" style="margin-top:0.75rem">Close</button>
    </div>
</div>

<div class="dl-progress-wrap" id="dl-progress" aria-live="polite">
    <div style="font-size:0.85rem;font-weight:600" id="dl-label">Download</div>
    <div class="dl-bar"><i id="dl-bar-inner"></i></div>
    <div class="muted mono" id="dl-meta" style="margin-top:0.25rem;font-size:0.8rem"></div>
</div>

<script>
(function () {
    const apiBase = <?php echo json_encode(str_replace('\\', '/', basename($_SERVER['SCRIPT_NAME'] ?? 'index.php')), JSON_UNESCAPED_SLASHES); ?>;

    function setTheme(mode) {
        document.documentElement.setAttribute('data-theme', mode);
        try { localStorage.setItem('fm_theme', mode); } catch (e) {}
    }
    (function initTheme() {
        try {
            const saved = localStorage.getItem('fm_theme');
            if (saved === 'dark' || saved === 'light') setTheme(saved);
            else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) setTheme('dark');
        } catch (e) {}
    })();
    document.getElementById('btn-theme').addEventListener('click', function () {
        const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
        setTheme(cur === 'dark' ? 'light' : 'dark');
    });

    document.getElementById('btn-copy-crumb').addEventListener('click', async function () {
        const t = document.getElementById('breadcrumb-path').textContent.trim();
        try {
            await navigator.clipboard.writeText(t);
            this.textContent = 'Copied';
            setTimeout(() => { this.textContent = 'Copy path'; }, 1400);
        } catch (e) {
            prompt('Copy path:', t);
        }
    });

    const loginModal = document.getElementById('modal-login');
    document.getElementById('btn-login') && document.getElementById('btn-login').addEventListener('click', function () {
        loginModal.classList.add('show');
    });
    document.getElementById('login-cancel').addEventListener('click', function () {
        loginModal.classList.remove('show');
    });
    loginModal.addEventListener('click', function (ev) {
        if (ev.target === loginModal) loginModal.classList.remove('show');
    });

    const previewModal = document.getElementById('modal-preview');
    const previewBody = document.getElementById('preview-body');
    document.querySelectorAll('.btn-preview').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const rel = btn.getAttribute('data-rel');
            const url = apiBase + '?preview=' + encodeURIComponent(rel);
            previewBody.innerHTML = '';
            const ext = rel.split('.').pop().toLowerCase();
            const imageExt = {png:1,jpg:1,jpeg:1,gif:1,webp:1,svg:1,ico:1};
            const pdfExt = {pdf:1};
            if (imageExt[ext]) {
                const img = document.createElement('img');
                img.src = url;
                img.alt = rel;
                img.style.maxWidth = '100%';
                img.style.height = 'auto';
                previewBody.appendChild(img);
            } else if (pdfExt[ext]) {
                const iframe = document.createElement('iframe');
                iframe.className = 'preview-frame';
                iframe.src = url;
                previewBody.appendChild(iframe);
            } else {
                fetch(url).then(function (r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.text();
                }).then(function (txt) {
                    const pre = document.createElement('pre');
                    pre.className = 'preview-text mono';
                    pre.textContent = txt;
                    previewBody.appendChild(pre);
                }).catch(function () {
                    previewBody.textContent = 'Could not load preview.';
                });
            }
            document.getElementById('preview-title').textContent = 'Preview: ' + rel;
            previewModal.classList.add('show');
        });
    });
    document.getElementById('preview-close').addEventListener('click', function () {
        previewModal.classList.remove('show');
        previewBody.innerHTML = '';
    });
    previewModal.addEventListener('click', function (ev) {
        if (ev.target === previewModal) {
            previewModal.classList.remove('show');
            previewBody.innerHTML = '';
        }
    });

    const hashModal = document.getElementById('modal-hashes');
    const hashBody = document.getElementById('hash-body');
    document.querySelectorAll('.btn-hashes').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const rel = btn.getAttribute('data-rel');
            hashBody.textContent = 'Loading…';
            hashModal.classList.add('show');
            fetch(apiBase + '?api=hashes&path=' + encodeURIComponent(rel))
                .then(function (r) { return r.json(); })
                .then(function (j) {
                    if (!j.ok) { hashBody.textContent = j.error || 'Error'; return; }
                    hashBody.innerHTML =
                        '<div><strong>MD5</strong><br>' + j.md5 + '</div>' +
                        '<div><strong>SHA1</strong><br>' + j.sha1 + '</div>' +
                        '<div><strong>SHA256</strong><br>' + j.sha256 + '</div>';
                })
                .catch(function () { hashBody.textContent = 'Request failed'; });
        });
    });
    document.getElementById('hash-close').addEventListener('click', function () { hashModal.classList.remove('show'); });
    hashModal.addEventListener('click', function (ev) { if (ev.target === hashModal) hashModal.classList.remove('show'); });

    document.querySelectorAll('.dir-size').forEach(function (el) {
        const p = el.getAttribute('data-path');
        fetch(apiBase + '?api=dirsize&path=' + encodeURIComponent(p))
            .then(function (r) { return r.json(); })
            .then(function (j) {
                el.textContent = j.ok ? j.formatted : '—';
            })
            .catch(function () { el.textContent = '—'; });
    });

    const renameModal = document.getElementById('modal-rename');
    document.querySelectorAll('.btn-rename').forEach(function (btn) {
        btn.addEventListener('click', function () {
            document.getElementById('rename-path').value = btn.getAttribute('data-rel');
            document.getElementById('rename-input').value = btn.getAttribute('data-name');
            renameModal.classList.add('show');
        });
    });
    document.getElementById('rename-cancel').addEventListener('click', function () { renameModal.classList.remove('show'); });
    renameModal.addEventListener('click', function (ev) { if (ev.target === renameModal) renameModal.classList.remove('show'); });

    const moveModal = document.getElementById('modal-move');
    document.querySelectorAll('.btn-move').forEach(function (btn) {
        btn.addEventListener('click', function () {
            document.getElementById('move-path').value = btn.getAttribute('data-rel');
            document.getElementById('move-dest').value = '';
            moveModal.classList.add('show');
        });
    });
    document.getElementById('move-cancel').addEventListener('click', function () { moveModal.classList.remove('show'); });
    moveModal.addEventListener('click', function (ev) { if (ev.target === moveModal) moveModal.classList.remove('show'); });

    const serverModal = document.getElementById('modal-server');
    const serverBody = document.getElementById('server-body');
    document.getElementById('btn-server').addEventListener('click', function () {
        serverBody.innerHTML = 'Loading…';
        serverModal.classList.add('show');
        fetch(apiBase + '?api=serverinfo')
            .then(function (r) { return r.json(); })
            .then(function (j) {
                if (!j.ok) { serverBody.textContent = 'Error'; return; }
                const rows = [
                    ['PHP version', j.php_version],
                    ['ZIP extension', j.zip_loaded ? 'Loaded' : 'Not loaded'],
                    ['Disk free', j.disk_free_formatted || 'n/a'],
                    ['Root path', j.document_root]
                ];
                serverBody.innerHTML = rows.map(function (kv) {
                    return '<div class="kv"><strong>' + kv[0] + '</strong><span class="mono" style="font-size:0.9rem;word-break:break-all">' + kv[1] + '</span></div>';
                }).join('');
            })
            .catch(function () { serverBody.textContent = 'Request failed'; });
    });
    document.getElementById('server-close').addEventListener('click', function () { serverModal.classList.remove('show'); });
    serverModal.addEventListener('click', function (ev) { if (ev.target === serverModal) serverModal.classList.remove('show'); });

    const dlBox = document.getElementById('dl-progress');
    const dlBar = document.getElementById('dl-bar-inner');
    const dlMeta = document.getElementById('dl-meta');
    const dlLabel = document.getElementById('dl-label');

    function humanBytes(n) {
        if (n < 1024) return n + ' B';
        var u = ['KB','MB','GB','TB'];
        var i = -1;
        do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
        return n.toFixed(n >= 10 || i === 0 ? 1 : 2) + ' ' + u[i];
    }

    document.querySelectorAll('a.dl-link').forEach(function (a) {
        a.addEventListener('click', function (ev) {
            ev.preventDefault();
            const href = a.getAttribute('href');
            dlBox.classList.add('show');
            dlLabel.textContent = 'Downloading…';
            dlBar.style.width = '0%';
            dlMeta.textContent = '';
            fetch(href).then(function (resp) {
                const total = parseInt(resp.headers.get('Content-Length') || '0', 10);
                if (!resp.body || !total) {
                    return resp.blob().then(function (blob) {
                        dlBar.style.width = '100%';
                        dlMeta.textContent = humanBytes(blob.size);
                        return blob;
                    });
                }
                const reader = resp.body.getReader();
                var received = 0;
                var chunks = [];
                function read() {
                    return reader.read().then(function (result) {
                        if (result.done) return;
                        chunks.push(result.value);
                        received += result.value.length;
                        dlBar.style.width = Math.min(100, Math.round((received / total) * 100)) + '%';
                        dlMeta.textContent = humanBytes(received) + ' / ' + humanBytes(total);
                        return read();
                    });
                }
                return read().then(function () {
                    return new Blob(chunks);
                });
            }).then(function (blob) {
                const name = (href.split('download=')[1] || 'download').split('&')[0];
                const decoded = decodeURIComponent(name);
                const url = URL.createObjectURL(blob);
                const tmp = document.createElement('a');
                tmp.href = url;
                tmp.download = decoded.split('/').pop();
                document.body.appendChild(tmp);
                tmp.click();
                tmp.remove();
                setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
                dlLabel.textContent = 'Complete';
            }).catch(function () {
                dlLabel.textContent = 'Failed — opening direct link';
                window.location.href = href;
            });
        });
    });
})();
</script>
</body>
</html>
