<?php
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
ini_set('display_errors', 0);

// Check if the timestamp query parameter is present to bypass browser/proxy caches
if (!isset($_GET['timestamp'])) {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $redirectUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $urlWithTimestamp = $redirectUrl . (strpos($_SERVER['REQUEST_URI'], '?') === false ? '?' : '&') . "timestamp=" . microtime(true);
    header("Location: $urlWithTimestamp", true, 301);
    exit;
}

// Load database connection
require_once __DIR__ . '/database.php';

// Include and execute the automated domain blocklist checks periodically
require_once __DIR__ . '/checker.php';
try {
    runAutoCheck($db);
} catch (Exception $e) {
    // Fail silently so redirection never gets disrupted by checker errors
}

// Parse slug from the request path
$requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '';
$slug = trim($requestPath, '/');

// Normalize slug (ignore index.php)
if ($slug === 'index.php') {
    $slug = '';
}

$redirect = null;
$is_custom_slug = false;

// 1. Try to find the custom slug if it's not empty
if (!empty($slug)) {
    $redirect = $db->getRedirectBySlug($slug);
    if ($redirect && intval($redirect['status']) === 1) {
        $is_custom_slug = true;
    } else {
        $redirect = null;
    }
}

// 2. If no custom slug was found, look up the 'default' slug
if (!$redirect) {
    $redirect = $db->getRedirectBySlug('default');
    if ($redirect && intval($redirect['status']) !== 1) {
        $redirect = null;
    }
}

// 3. Set the target redirect URL
$target_url = '';
$redirect_id = null;

if ($redirect) {
    $target_url = $redirect['target_url'];
    $redirect_id = $redirect['id'];
} else {
    // Fallback to settings fallback_url
    $target_url = $db->getSetting('fallback_url');
    if (empty($target_url)) {
        $target_url = 'https://cutt.ly/002wings';
    }
}

// 4. Log the click if a redirection row was matched
if ($redirect_id !== null) {
    try {
        // Increment click counter
        $db->incrementClicks($redirect_id);
        
        // Log details
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        }
        
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referrer = $_SERVER['HTTP_REFERER'] ?? '';
        
        $db->addClickLog($redirect_id, $ip, $ua, $referrer);
    } catch (Exception $e) {
        // Silently fail database logging errors so redirections still work
    }
}

// Helper to construct the target URL with query parameters forwarded correctly
function buildRedirectUrl($targetUrl, $isCustomSlug) {
    $queryString = parse_url($_SERVER['REQUEST_URI'], PHP_URL_QUERY) ?? '';
    
    // Strip the timestamp parameter
    $queryString = preg_replace('/(^|&)timestamp=[0-9.]+(\$|&)/', '$1', $queryString);
    $queryString = trim($queryString, '&');
    
    if ($isCustomSlug) {
        // Custom slug: append query parameters only
        if (!empty($queryString)) {
            $separator = (strpos($targetUrl, '?') === false) ? '?' : '&';
            return $targetUrl . $separator . $queryString;
        }
        return $targetUrl;
    } else {
        // Fallback or Default: append full path + query parameters
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '';
        $path = trim($path, '/');
        if ($path === 'index.php') {
            $path = '';
        }
        
        $redirectUrl = rtrim($targetUrl, '/');
        if (!empty($path)) {
            $redirectUrl .= '/' . $path;
        }
        if (!empty($queryString)) {
            $separator = (strpos($redirectUrl, '?') === false) ? '?' : '&';
            $redirectUrl .= $separator . $queryString;
        }
        return $redirectUrl;
    }
}

// Redirect to target URL
$final_destination = buildRedirectUrl($target_url, $is_custom_slug);
header("Location: " . $final_destination, true, 301);
exit;
?>
