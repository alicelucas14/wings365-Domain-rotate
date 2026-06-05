<?php
session_start();
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/checker.php';

// Brand ID Selection
if (isset($_GET['brand_id']) && in_array($_GET['brand_id'], ['1', '2', '3', '4'])) {
    $_SESSION['active_brand_id'] = intval($_GET['brand_id']);
    header('Location: admin.php');
    exit;
}
if (!isset($_SESSION['active_brand_id'])) {
    $_SESSION['active_brand_id'] = 1;
}
$active_brand_id = $_SESSION['active_brand_id'];

// Check if there are any users in the database
$user_count = $db->getUserCount();
$setup_mode = ($user_count === 0);

$error = $_SESSION['error'] ?? '';
$success = $_SESSION['success'] ?? '';
unset($_SESSION['error'], $_SESSION['success']);


// Helper to sanitize slug
function sanitize_slug($slug) {
    $slug = strtolower(trim($slug));
    $slug = preg_replace('/[^a-z0-9\-_]/', '', $slug); // Allow only letters, numbers, dashes, underscores
    return $slug;
}

// User Agent Helper
function parse_user_agent($ua) {
    if (empty($ua)) return 'Direct / Unknown';
    $browser = 'Unknown';
    $platform = 'Unknown';
    
    // Platform
    if (preg_match('/windows|win32/i', $ua)) $platform = 'Windows';
    elseif (preg_match('/macintosh|mac os x/i', $ua)) $platform = 'macOS';
    elseif (preg_match('/linux/i', $ua)) $platform = 'Linux';
    elseif (preg_match('/iphone|ipad|ipod/i', $ua)) $platform = 'iOS';
    elseif (preg_match('/android/i', $ua)) $platform = 'Android';
    
    // Browser
    if (preg_match('/opera|opr/i', $ua)) $browser = 'Opera';
    elseif (preg_match('/edge|edg/i', $ua)) $browser = 'Edge';
    elseif (preg_match('/chrome/i', $ua)) $browser = 'Chrome';
    elseif (preg_match('/safari/i', $ua)) $browser = 'Safari';
    elseif (preg_match('/firefox/i', $ua)) $browser = 'Firefox';
    elseif (preg_match('/msie|trident/i', $ua)) $browser = 'IE';
    
    return "$browser ($platform)";
}

// ----------------------------------------------------
// HANDLERS (UNAUTHENTICATED)
// ----------------------------------------------------

// Handle Setup Mode POST
if ($setup_mode && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'setup') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $security_question = trim($_POST['security_question'] ?? '');
    $security_answer = trim($_POST['security_answer'] ?? '');
    
    if (empty($username) || empty($password) || empty($security_question) || empty($security_answer)) {
        $error = 'All fields are required.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } else {
        try {
            // Insert admin user
            $userId = $db->addUser(
                $username,
                password_hash($password, PASSWORD_DEFAULT),
                $security_question,
                password_hash(strtolower($security_answer), PASSWORD_DEFAULT),
                'admin'
            );
            
            // Insert default redirect route if not exists for Brand 1
            if (!$db->getRedirectBySlugAndBrand('default', 1)) {
                $db->addRedirect('default', 'https://cutt.ly/002wings', 1, 1);
            }
            
            // Insert current hostname as active domain for Brand 1
            if (isset($_SERVER['HTTP_HOST'])) {
                $db->addDomain($_SERVER['HTTP_HOST'], 1);
            }
            
            $_SESSION['user_id'] = $userId;
            $_SESSION['username'] = $username;
            $_SESSION['role'] = 'admin';
            $_SESSION['logged_in'] = true;
            
            header('Location: admin.php');
            exit;
        } catch (Exception $e) {
            $error = 'Setup failed: ' . $e->getMessage();
        }
    }
}

// Handle Login POST
if (!$setup_mode && !isset($_SESSION['logged_in']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    $user = $db->getUserByUsername($username);
    
    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['logged_in'] = true;
        header('Location: admin.php');
        exit;
    } else {
        $error = 'Invalid username or password.';
    }
}

// Handle Password Recovery flow
$recovery_stage = 0; // 0=none, 1=show question, 2=reset password
$recovery_user = null;

if (isset($_GET['recovery'])) {
    $recovery_stage = 1;
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
        $username = trim($_POST['username'] ?? '');
        $recovery_user = $db->getUserByUsername($username);
        
        if (!$recovery_user) {
            $error = 'Username not found.';
        } else {
            if ($_POST['action'] === 'check_username') {
                $recovery_stage = 2; // Move to answer verification stage
            } elseif ($_POST['action'] === 'verify_answer') {
                $recovery_stage = 2;
                $answer = trim($_POST['security_answer'] ?? '');
                if (password_verify(strtolower($answer), $recovery_user['security_answer_hash'])) {
                    // Answer matches, move to password reset
                    $recovery_stage = 3;
                } else {
                    $error = 'Incorrect security answer.';
                }
            } elseif ($_POST['action'] === 'reset_password') {
                $recovery_stage = 3;
                $new_pw = $_POST['new_password'] ?? '';
                $confirm_pw = $_POST['confirm_new_password'] ?? '';
                
                if (strlen($new_pw) < 6) {
                    $error = 'Password must be at least 6 characters.';
                } elseif ($new_pw !== $confirm_pw) {
                    $error = 'Passwords do not match.';
                } else {
                    $db->updateUserPassword($recovery_user['id'], password_hash($new_pw, PASSWORD_DEFAULT));
                    $success = 'Password reset successfully! You can now log in.';
                    $recovery_stage = 0;
                }
            }
        }
    }
}

// ----------------------------------------------------
// AUTHENTICATED CONSOLE HANDLERS
// ----------------------------------------------------
$is_authenticated = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

if ($is_authenticated) {
    // Handle Logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: admin.php');
        exit;
    }
    
    // TAB Control
    $current_tab = $_GET['tab'] ?? 'overview';
    
    // Add Link POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_link') {
        $slug = sanitize_slug($_POST['slug'] ?? '');
        $target_url = trim($_POST['target_url'] ?? '');
        $status = isset($_POST['status']) ? 1 : 0;
        
        if (empty($slug) || empty($target_url)) {
            $_SESSION['error'] = 'Slug and Target URL are required.';
        } elseif (!filter_var($target_url, FILTER_VALIDATE_URL)) {
            $_SESSION['error'] = 'Invalid Target URL format. Please include http:// or https://.';
        } else {
            // Check uniqueness specifically for this brand
            if ($db->getRedirectBySlugAndBrand($slug, $active_brand_id)) {
                $_SESSION['error'] = "The slug '{$slug}' already exists.";
            } else {
                if ($db->addRedirect($slug, $target_url, $status, $active_brand_id)) {
                    $_SESSION['success'] = 'Redirect link created successfully!';
                } else {
                    $_SESSION['error'] = 'Failed to create redirect link.';
                }
            }
        }
        header('Location: admin.php?tab=redirects');
        exit;
    }
    
    // Edit Link POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'edit_link') {
        $id = intval($_POST['id'] ?? 0);
        $slug = sanitize_slug($_POST['slug'] ?? '');
        $target_url = trim($_POST['target_url'] ?? '');
        $status = isset($_POST['status']) ? 1 : 0;
        
        if (empty($slug) || empty($target_url)) {
            $_SESSION['error'] = 'All fields are required.';
        } elseif (!filter_var($target_url, FILTER_VALIDATE_URL)) {
            $_SESSION['error'] = 'Invalid Target URL format. Please include http:// or https://.';
        } else {
            // Check uniqueness except itself within this brand
            $existing = $db->getRedirectBySlugAndBrand($slug, $active_brand_id);
            if ($existing && intval($existing['id']) !== $id) {
                $_SESSION['error'] = "The slug '{$slug}' is already taken by another link.";
            } else {
                if ($db->updateRedirect($id, $slug, $target_url, $status)) {
                    $_SESSION['success'] = 'Redirect link updated successfully!';
                } else {
                    $_SESSION['error'] = 'Failed to update redirect link.';
                }
            }
        }
        header('Location: admin.php?tab=redirects');
        exit;
    }
    
    // Delete Link GET
    if (isset($_GET['delete_link'])) {
        $id = intval($_GET['delete_link']);
        $link = $db->getRedirectById($id);
        
        if ($link && $link['slug'] === 'default') {
            $_SESSION['error'] = 'The default fallback route cannot be deleted, but you can edit its target.';
        } else {
            if ($db->deleteRedirect($id)) {
                $_SESSION['success'] = 'Redirect link deleted successfully.';
            } else {
                $_SESSION['error'] = 'Failed to delete redirect link.';
            }
        }
        header('Location: admin.php?tab=redirects');
        exit;
    }
    
    // Clear Logs POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'clear_logs') {
        $db->clearLogs($active_brand_id);
        $_SESSION['success'] = 'Click logs cleared and redirect counters reset for the active brand!';
        header('Location: admin.php?tab=overview');
        exit;
    }
    
    // Add User POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_user' && $_SESSION['role'] === 'admin') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? 'operator';
        
        if (empty($username) || empty($password)) {
            $_SESSION['error'] = 'All fields are required.';
        } elseif (strlen($password) < 6) {
            $_SESSION['error'] = 'Password must be at least 6 characters.';
        } else {
            if ($db->getUserByUsername($username)) {
                $_SESSION['error'] = 'Username already exists.';
            } else {
                $db->addUser($username, password_hash($password, PASSWORD_DEFAULT), '', '', $role);
                $_SESSION['success'] = "User account '{$username}' created.";
            }
        }
        header('Location: admin.php?tab=security');
        exit;
    }
    
    // Delete User GET
    if (isset($_GET['delete_user']) && $_SESSION['role'] === 'admin') {
        $id = intval($_GET['delete_user']);
        if ($id === intval($_SESSION['user_id'])) {
            $_SESSION['error'] = 'You cannot delete your own account.';
        } else {
            $db->deleteUser($id);
            $_SESSION['success'] = 'User account deleted.';
        }
        header('Location: admin.php?tab=security');
        exit;
    }
    
    // Change Password / Recovery POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'security_update') {
        $current_pw = $_POST['current_password'] ?? '';
        $new_pw = $_POST['new_password'] ?? '';
        $confirm_pw = $_POST['confirm_new'] ?? '';
        $sec_question = trim($_POST['security_question'] ?? '');
        $sec_answer = trim($_POST['security_answer'] ?? '');
        
        $user = $db->getUserById($_SESSION['user_id']);
        
        if (!password_verify($current_pw, $user['password_hash'])) {
            $_SESSION['error'] = 'Current password is incorrect.';
        } else {
            try {
                // Password change
                if (!empty($new_pw)) {
                    if (strlen($new_pw) < 6) {
                        throw new Exception('New password must be at least 6 characters.');
                    } elseif ($new_pw !== $confirm_pw) {
                        throw new Exception('New passwords do not match.');
                    } else {
                        $db->updateUserPassword($_SESSION['user_id'], password_hash($new_pw, PASSWORD_DEFAULT));
                    }
                }
                
                // Security question update
                if (!empty($sec_question) && !empty($sec_answer)) {
                    $db->updateUserSecurity(
                        $_SESSION['user_id'],
                        $sec_question,
                        password_hash(strtolower($sec_answer), PASSWORD_DEFAULT)
                    );
                }
                
                $_SESSION['success'] = 'Security settings updated successfully!';
            } catch (Exception $ex) {
                $_SESSION['error'] = $ex->getMessage();
            }
        }
        header('Location: admin.php?tab=security');
        exit;
    }

    // Add Domain POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_domain') {
        $new_domain = trim($_POST['new_domain'] ?? '');
        if (empty($new_domain)) {
            $_SESSION['error'] = 'Domain name cannot be empty.';
        } else {
            if ($db->addDomain($new_domain, $active_brand_id)) {
                $_SESSION['success'] = "Domain '{$new_domain}' added to your list.";
            } else {
                $_SESSION['error'] = "Failed to add domain. It may already exist.";
            }
        }
        header('Location: admin.php?tab=domains');
        exit;
    }

    // Delete Domain GET
    if (isset($_GET['delete_domain'])) {
        $id = intval($_GET['delete_domain']);
        $db->deleteDomain($id);
        $_SESSION['success'] = 'Domain deleted successfully.';
        header('Location: admin.php?tab=domains');
        exit;
    }

    // Manual Force Check Domains GET
    if (isset($_GET['check_domains'])) {
        $rotated = runAutoCheck($db, true);
        if ($rotated) {
            $_SESSION['success'] = 'Blacklist verification complete: Blocked domain detected and successfully rotated to clean backup domain!';
        } else {
            $_SESSION['success'] = 'Blacklist verification complete: Active domain is clean!';
        }
        header('Location: admin.php?tab=domains');
        exit;
    }

    // Force Rotate Domain GET
    if (isset($_GET['rotate_domain'])) {
        $db->rotateDomain($active_brand_id, 'Manually rotated by admin.');
        $_SESSION['success'] = 'Domain rotated to next clean backup successfully.';
        header('Location: admin.php?tab=domains');
        exit;
    }
    
    // Save Settings POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save_settings') {
        $brand_name = trim($_POST['brand_name'] ?? '');
        $fallback_url = trim($_POST['fallback_url'] ?? '');
        $domain_override = trim($_POST['domain_override'] ?? '');
        $safe_browsing_key = trim($_POST['safe_browsing_key'] ?? '');
        $check_interval_hours = max(0.01, floatval($_POST['check_interval_hours'] ?? 6));
        
        if (empty($brand_name)) {
            $_SESSION['error'] = 'Brand Name cannot be empty.';
        } elseif (empty($fallback_url)) {
            $_SESSION['error'] = 'Fallback URL cannot be empty.';
        } elseif (!filter_var($fallback_url, FILTER_VALIDATE_URL)) {
            $_SESSION['error'] = 'Invalid fallback URL format.';
        } else {
            $db->updateBrandSetting($active_brand_id, 'name', $brand_name);
            $db->updateBrandSetting($active_brand_id, 'fallback_url', $fallback_url);
            $db->updateBrandSetting($active_brand_id, 'domain_override', rtrim($domain_override, '/'));
            
            $db->updateSetting('safe_browsing_key', $safe_browsing_key);
            $db->updateSetting('check_interval_hours', $check_interval_hours);
            $_SESSION['success'] = 'Settings updated successfully!';
        }
        header('Location: admin.php?tab=settings');
        exit;
    }
    
    // CSV Export Handler
    if (isset($_GET['export']) && $_GET['export'] === 'csv') {
        $brand_name_setting = $db->getBrandSetting($active_brand_id, 'name');
        if (empty($brand_name_setting)) {
            $brand_name_setting = 'Brand_' . $active_brand_id;
        }
        $brand_name_slug = preg_replace('/[^a-z0-9]/i', '_', $brand_name_setting);
        
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=' . $brand_name_slug . '_redirects_export.csv');
        $output = fopen('php://output', 'w');
        fputcsv($output, ['ID', 'Slug', 'Target URL', 'Status', 'Total Clicks', 'Created At']);
        
        $redirects = $db->getRedirects($active_brand_id);
        usort($redirects, function($a, $b) {
            return intval($a['id']) <=> intval($b['id']);
        });
        
        foreach ($redirects as $row) {
            fputcsv($output, [
                $row['id'],
                $row['slug'],
                $row['target_url'],
                $row['status'] ? 'Active' : 'Inactive',
                $row['clicks'],
                $row['created_at']
            ]);
        }
        fclose($output);
        exit;
    }
}

// ----------------------------------------------------
// RESOLVE DYNAMIC VALUES FOR VIEW
// ----------------------------------------------------
$brand_name = $db->getBrandSetting($active_brand_id, 'name');
if (empty($brand_name)) {
    $brand_name = 'Brand ' . $active_brand_id;
}
$fallback_url = $db->getBrandSetting($active_brand_id, 'fallback_url');
if (empty($fallback_url)) {
    $fallback_url = 'https://cutt.ly/002wings';
}
$domain_override = $db->getBrandSetting($active_brand_id, 'domain_override');
$safe_browsing_key = $db->getSetting('safe_browsing_key');
$check_interval_hours = floatval($db->getSetting('check_interval_hours'));
if ($check_interval_hours <= 0) $check_interval_hours = 6;

// Determine active domain display
if (!empty($domain_override)) {
    $domain_url = $domain_override . '/';
} else {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $domain_url = $protocol . $db->getActiveDomain($active_brand_id) . str_replace('admin.php', '', $_SERVER['SCRIPT_NAME']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wings365 — Console</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #05060a;
            --surface-color: rgba(16, 18, 30, 0.75);
            --sidebar-color: rgba(11, 12, 22, 0.9);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-primary: #6366f1;
            --accent-secondary: #a855f7;
            --accent-gradient: linear-gradient(135deg, #6366f1, #a855f7);
            --success-color: #10b981;
            --success-bg: rgba(16, 185, 129, 0.1);
            --success-border: rgba(16, 185, 129, 0.25);
            --error-color: #f43f5e;
            --error-bg: rgba(244, 63, 94, 0.1);
            --error-border: rgba(244, 63, 94, 0.25);
            --font-main: 'Outfit', sans-serif;
            --font-heading: 'Plus Jakarta Sans', sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.12) 0px, transparent 40%),
                radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.1) 0px, transparent 40%);
            background-attachment: fixed;
            color: var(--text-primary);
            font-family: var(--font-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

        /* Layout Structure */
        .wrapper {
            display: flex;
            flex-grow: 1;
            width: 100%;
        }

        @media (max-width: 900px) {
            .wrapper {
                flex-direction: column;
            }
        }

        /* Sidebar Navigation */
        .sidebar {
            width: 260px;
            background: var(--sidebar-color);
            border-right: 1px solid var(--border-color);
            padding: 2rem 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 2rem;
            flex-shrink: 0;
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
        }

        @media (max-width: 900px) {
            .sidebar {
                width: 100%;
                border-right: none;
                border-bottom: 1px solid var(--border-color);
                padding: 1.5rem 1rem;
                gap: 1.5rem;
            }
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            text-decoration: none;
            color: var(--text-primary);
            font-family: var(--font-heading);
            font-weight: 700;
            font-size: 1.5rem;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }

        .logo svg {
            stroke: url(#logo-grad-side);
        }

        .nav-links {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            list-style: none;
        }

        @media (max-width: 900px) {
            .nav-links {
                flex-direction: row;
                flex-wrap: wrap;
            }
        }

        .nav-item a {
            display: flex;
            align-items: center;
            gap: 0.85rem;
            padding: 0.8rem 1rem;
            color: var(--text-secondary);
            text-decoration: none;
            border-radius: 12px;
            font-weight: 500;
            font-size: 0.95rem;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .nav-item a:hover {
            color: var(--text-primary);
            background: rgba(255, 255, 255, 0.04);
        }

        .nav-item.active a {
            color: white;
            background: var(--accent-gradient);
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.25);
        }

        .user-profile {
            margin-top: auto;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 0.85rem 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
        }

        @media (max-width: 900px) {
            .user-profile {
                margin-top: 0;
            }
        }

        .profile-info {
            display: flex;
            flex-direction: column;
            gap: 0.15rem;
            overflow: hidden;
        }

        .profile-name {
            font-weight: 600;
            font-size: 0.9rem;
            text-overflow: ellipsis;
            overflow: hidden;
            white-space: nowrap;
        }

        .profile-role {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-icon {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 0.35rem;
            border-radius: 8px;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .btn-icon:hover {
            color: var(--error-color);
            background: rgba(244, 63, 94, 0.1);
        }

        /* Main Content Container */
        .content-area {
            flex-grow: 1;
            padding: 2.5rem;
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
        }

        @media (max-width: 900px) {
            .content-area {
                padding: 1.5rem 1rem;
            }
        }

        /* Auth Container Forms */
        .auth-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            flex-grow: 1;
            padding: 2rem 1rem;
        }

        .auth-card {
            max-width: 440px;
            width: 100%;
            background: var(--surface-color);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--border-color);
            border-radius: 28px;
            padding: 2.5rem;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.4);
            animation: slideUp 0.35s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(15px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .auth-card h2 {
            font-family: var(--font-heading);
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            letter-spacing: -0.5px;
        }

        .auth-card p {
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-bottom: 2rem;
            line-height: 1.5;
        }

        .auth-footer-links {
            margin-top: 1.5rem;
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
        }

        .auth-footer-links a {
            color: var(--accent-primary);
            text-decoration: none;
        }

        .auth-footer-links a:hover {
            text-decoration: underline;
        }

        /* General UI Elements */
        .alert {
            padding: 1rem 1.2rem;
            border-radius: 14px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            animation: fadeIn 0.25s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .alert-error {
            background-color: var(--error-bg);
            border: 1px solid var(--error-border);
            color: var(--error-color);
        }

        .alert-success {
            background-color: var(--success-bg);
            border: 1px solid var(--success-border);
            color: var(--success-color);
        }

        .form-group {
            margin-bottom: 1.25rem;
        }

        .form-group label {
            display: block;
            font-size: 0.825rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }

        .input-wrapper {
            position: relative;
        }

        .input-wrapper svg {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-secondary);
            pointer-events: none;
            transition: color 0.2s ease;
        }

        .form-input, .form-select {
            width: 100%;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.8rem 1rem 0.8rem 2.75rem;
            border-radius: 14px;
            font-family: var(--font-main);
            font-size: 0.95rem;
            outline: none;
            transition: all 0.2s ease;
        }

        .form-select {
            appearance: none;
            -webkit-appearance: none;
            background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' fill='none' stroke='%239ca3af' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polyline points='6 9 12 15 18 9'/></svg>");
            background-repeat: no-repeat;
            background-position: right 1rem center;
            background-size: 1.2rem;
            cursor: pointer;
        }

        .form-input:focus, .form-select:focus {
            background: rgba(255, 255, 255, 0.07);
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.12);
        }

        .form-input:focus + svg {
            color: var(--accent-primary);
        }

        .submit-btn {
            background: var(--accent-gradient);
            color: white;
            border: none;
            padding: 0.85rem 1.8rem;
            border-radius: 14px;
            font-family: var(--font-main);
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.25);
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .submit-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.35);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            box-shadow: none;
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-1px);
            box-shadow: none;
        }

        .btn-danger {
            background: rgba(244, 63, 94, 0.1);
            color: var(--error-color);
            border: 1px solid var(--error-border);
            box-shadow: none;
        }

        .btn-danger:hover {
            background: var(--error-color);
            color: white;
            border-color: var(--error-color);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
        }

        /* Overview Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stats-card {
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1.25rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }

        .stats-icon {
            width: 52px;
            height: 52px;
            border-radius: 12px;
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.15);
            color: var(--accent-primary);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .stats-card:nth-child(2) .stats-icon {
            background: rgba(168, 85, 247, 0.1);
            border-color: rgba(168, 85, 247, 0.15);
            color: var(--accent-secondary);
        }

        .stats-card:nth-child(3) .stats-icon {
            background: rgba(16, 185, 129, 0.1);
            border-color: rgba(16, 185, 129, 0.15);
            color: var(--success-color);
        }

        .stats-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .stats-title {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .stats-value {
            font-family: var(--font-heading);
            font-weight: 700;
            font-size: 1.75rem;
            line-height: 1.2;
        }

        /* Dashboard Grid Layout */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1.6fr 1fr;
            gap: 2rem;
        }

        @media (max-width: 900px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        .card {
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            padding: 2rem;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
            margin-bottom: 2rem;
        }

        .card-header-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
        }

        .card-title {
            font-family: var(--font-heading);
            font-size: 1.25rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .card-title svg {
            color: var(--accent-primary);
        }

        /* SVG Bar list for stats */
        .bar-list {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }

        .bar-item {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }

        .bar-item-info {
            display: flex;
            justify-content: space-between;
            font-size: 0.9rem;
            font-weight: 500;
        }

        .bar-slug {
            color: var(--text-primary);
            font-family: monospace;
            background: rgba(255, 255, 255, 0.05);
            padding: 0.1rem 0.4rem;
            border-radius: 5px;
        }

        .bar-clicks {
            color: var(--accent-primary);
            font-weight: 600;
        }

        .bar-track {
            height: 8px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 4px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        .bar-fill {
            height: 100%;
            background: var(--accent-gradient);
            border-radius: 4px;
            transition: width 0.6s ease-out;
        }

        /* Tables */
        .table-container {
            width: 100%;
            overflow-x: auto;
            border-radius: 16px;
            border: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.01);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }

        th {
            background: rgba(255, 255, 255, 0.02);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            vertical-align: middle;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.015);
        }

        .badge {
            padding: 0.25rem 0.5rem;
            border-radius: 8px;
            font-size: 0.725rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.25px;
            display: inline-flex;
            align-items: center;
        }

        .badge-active {
            background: rgba(16, 185, 129, 0.12);
            color: var(--success-color);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .badge-inactive {
            background: rgba(244, 63, 94, 0.12);
            color: var(--error-color);
            border: 1px solid rgba(244, 63, 94, 0.2);
        }

        .slug-url {
            font-family: monospace;
            font-size: 0.95rem;
            color: var(--text-primary);
            word-break: break-all;
        }

        .target-url {
            color: var(--text-secondary);
            font-size: 0.85rem;
            word-break: break-all;
        }

        /* Actions group */
        .actions-cell {
            display: flex;
            gap: 0.50rem;
        }

        .action-btn {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.45rem 0.75rem;
            border-radius: 8px;
            font-size: 0.8rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            font-family: var(--font-main);
            font-weight: 500;
            transition: all 0.2s ease;
        }

        .action-btn:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(255, 255, 255, 0.15);
        }

        .action-btn-danger:hover {
            background: rgba(244, 63, 94, 0.12);
            border-color: var(--error-border);
            color: var(--error-color);
        }

        /* Modal Overlay */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(8px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.25s ease;
        }

        .modal-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-card {
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            max-width: 500px;
            width: 90%;
            padding: 2rem;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3);
            transform: scale(0.95);
            transition: transform 0.25s ease;
        }

        .modal-overlay.active .modal-card {
            transform: scale(1);
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 0.75rem;
            margin-top: 1.5rem;
        }

        /* Checkbox styling */
        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            user-select: none;
        }

        .checkbox-container input {
            display: none;
        }

        .checkbox-checkmark {
            width: 20px;
            height: 20px;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .checkbox-container input:checked + .checkbox-checkmark {
            background: var(--accent-gradient);
            border-color: transparent;
        }

        .checkbox-checkmark svg {
            color: white;
            display: none;
        }

        .checkbox-container input:checked + .checkbox-checkmark svg {
            display: block;
        }

        /* Filter header */
        .filter-header {
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }

        /* Copy notification badge toast */
        .toast-copy {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--success-color);
            color: white;
            padding: 0.8rem 1.5rem;
            border-radius: 12px;
            font-weight: 600;
            box-shadow: 0 10px 25px rgba(16, 185, 129, 0.3);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            z-index: 2000;
        }

        .toast-copy.active {
            transform: translateY(0);
            opacity: 1;
        }

        footer {
            padding: 2rem;
            text-align: center;
            color: rgba(255, 255, 255, 0.15);
            font-size: 0.8rem;
            border-top: 1px solid rgba(255, 255, 255, 0.03);
            margin-top: auto;
        }
    </style>
</head>
<body>
    <svg style="position: absolute; width: 0; height: 0;" width="0" height="0">
        <defs>
            <linearGradient id="logo-grad-side" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#6366f1" />
                <stop offset="100%" stop-color="#a855f7" />
            </linearGradient>
        </defs>
    </svg>

    <div class="toast-copy" id="toast-copy">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
        <span>Link Copied!</span>
    </div>

    <?php if (!$is_authenticated): ?>
        <div class="auth-wrapper">
            <?php if ($setup_mode): ?>
                <!-- Setup Screen -->
                <div class="auth-card">
                    <h2>Initialize System</h2>
                    <p>Create the primary administrator account and security recovery question.</p>

                    <?php if ($error): ?>
                        <div class="alert alert-error">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                            <span><?php echo htmlspecialchars($error); ?></span>
                        </div>
                    <?php endif; ?>

                    <form method="POST">
                        <input type="hidden" name="action" value="setup">
                        
                        <div class="form-group">
                            <label for="username">Admin Username</label>
                            <div class="input-wrapper">
                                <input type="text" name="username" id="username" class="form-input" placeholder="e.g. admin" required autofocus>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="password">Password</label>
                            <div class="input-wrapper">
                                <input type="password" name="password" id="password" class="form-input" placeholder="Create secure password" required>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="confirm_password">Confirm Password</label>
                            <div class="input-wrapper">
                                <input type="password" name="confirm_password" id="confirm_password" class="form-input" placeholder="Confirm password" required>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="security_question">Security Recovery Question</label>
                            <div class="input-wrapper">
                                <select name="security_question" id="security_question" class="form-select" required>
                                    <option value="What is the name of your first school?">What is the name of your first school?</option>
                                    <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                                    <option value="What city were you born in?">What city were you born in?</option>
                                    <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
                                    <option value="What was the model of your first car?">What was the model of your first car?</option>
                                </select>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="security_answer">Security Answer</label>
                            <div class="input-wrapper">
                                <input type="text" name="security_answer" id="security_answer" class="form-input" placeholder="Provide answer for recovery" required>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><key>🔑</key><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.778-7.778zM12 5.79l7.21 7.21M17 11l-3 3M19 9l-3 3"></path></svg>
                            </div>
                        </div>

                        <button type="submit" class="submit-btn" style="width: 100%; margin-top: 1rem;">Complete Setup</button>
                    </form>
                </div>
            <?php elseif ($recovery_stage > 0): ?>
                <!-- Password Recovery Screen -->
                <div class="auth-card">
                    <h2>Password Recovery</h2>
                    <p>Recover your credentials via security verification.</p>

                    <?php if ($error): ?>
                        <div class="alert alert-error">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                            <span><?php echo htmlspecialchars($error); ?></span>
                        </div>
                    <?php endif; ?>

                    <form method="POST">
                        <?php if ($recovery_stage === 1): ?>
                            <!-- Stage 1: Input username -->
                            <input type="hidden" name="action" value="check_username">
                            <div class="form-group">
                                <label for="username">Username</label>
                                <div class="input-wrapper">
                                    <input type="text" name="username" id="username" class="form-input" placeholder="Your username" required autofocus>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                                </div>
                            </div>
                            <button type="submit" class="submit-btn" style="width: 100%;">Verify Account</button>
                        <?php elseif ($recovery_stage === 2 && $recovery_user): ?>
                            <!-- Stage 2: Question and Answer -->
                            <input type="hidden" name="action" value="verify_answer">
                            <input type="hidden" name="username" value="<?php echo htmlspecialchars($recovery_user['username']); ?>">
                            
                            <div class="form-group">
                                <label>Security Question</label>
                                <p style="color: var(--text-primary); font-size: 1.05rem; font-weight: 500; margin-bottom: 1rem; text-align: left; padding: 0.5rem 0;">
                                    <?php echo htmlspecialchars($recovery_user['security_question']); ?>
                                </p>
                            </div>
                            
                            <div class="form-group">
                                <label for="security_answer">Your Answer</label>
                                <div class="input-wrapper">
                                    <input type="text" name="security_answer" id="security_answer" class="form-input" placeholder="Your answer" required autofocus>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><key>🔑</key><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.778-7.778zM12 5.79l7.21 7.21M17 11l-3 3M19 9l-3 3"></path></svg>
                                </div>
                            </div>
                            <button type="submit" class="submit-btn" style="width: 100%;">Submit Verification</button>
                        <?php elseif ($recovery_stage === 3 && $recovery_user): ?>
                            <!-- Stage 3: Input new password -->
                            <input type="hidden" name="action" value="reset_password">
                            <input type="hidden" name="username" value="<?php echo htmlspecialchars($recovery_user['username']); ?>">
                            <input type="hidden" name="security_answer" value="<?php echo htmlspecialchars($_POST['security_answer'] ?? ''); ?>">
                            
                            <div class="form-group">
                                <label for="new_password">New Password</label>
                                <div class="input-wrapper">
                                    <input type="password" name="new_password" id="new_password" class="form-input" placeholder="Enter new password" required autofocus>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="confirm_new_password">Confirm New Password</label>
                                <div class="input-wrapper">
                                    <input type="password" name="confirm_new_password" id="confirm_new_password" class="form-input" placeholder="Confirm new password" required>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                </div>
                            </div>
                            <button type="submit" class="submit-btn" style="width: 100%;">Change & Save Password</button>
                        <?php endif; ?>
                    </form>
                    
                    <div class="auth-footer-links">
                        <a href="admin.php">Back to Login</a>
                    </div>
                </div>
            <?php else: ?>
                <!-- Login Screen -->
                <div class="auth-card">
                    <h2>Console Login</h2>
                    <p>Enter your credentials to unlock the redirect management dashboard.</p>

                    <?php if ($success): ?>
                        <div class="alert alert-success">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                            <span><?php echo htmlspecialchars($success); ?></span>
                        </div>
                    <?php endif; ?>

                    <?php if ($error): ?>
                        <div class="alert alert-error">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                            <span><?php echo htmlspecialchars($error); ?></span>
                        </div>
                    <?php endif; ?>

                    <form method="POST">
                        <input type="hidden" name="action" value="login">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <div class="input-wrapper">
                                <input type="text" name="username" id="username" class="form-input" placeholder="Enter username" required autofocus>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <div class="input-wrapper">
                                <input type="password" name="password" id="password" class="form-input" placeholder="Enter password" required>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            </div>
                        </div>
                        <button type="submit" class="submit-btn" style="width: 100%; margin-top: 0.5rem;">Access Console</button>
                    </form>

                    <div class="auth-footer-links">
                        <a href="admin.php?recovery=1">Forgot Password?</a>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    <?php else: ?>
        <!-- Console Panel wrapper -->
        <div class="wrapper">
            <!-- Sidebar Panel -->
            <aside class="sidebar">
                <a href="admin.php" class="logo">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                    </svg>
                    <?php echo htmlspecialchars($brand_name); ?>
                </a>
                
                <!-- Brand Switcher -->
                <div class="brand-switcher-container" style="padding: 0.5rem 1.25rem 1rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); margin-bottom: 1rem;">
                    <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.5rem; font-weight: 700;">System Context</div>
                    <div class="brand-pills" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.25rem; background: rgba(255, 255, 255, 0.03); padding: 0.2rem; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.05);">
                        <?php for ($i = 1; $i <= 4; $i++): 
                            $b_name_pill = $db->getBrandSetting($i, 'name');
                            if (empty($b_name_pill)) $b_name_pill = 'Brand ' . $i;
                            // Extract first 4 chars of name or acronym for pill
                            $pill_label = $b_name_pill;
                            if (strlen($b_name_pill) > 6) {
                                $pill_label = substr($b_name_pill, 0, 5) . '..';
                            }
                            $is_active = (intval($active_brand_id) === $i);
                        ?>
                            <a href="admin.php?brand_id=<?php echo $i; ?>" class="brand-pill-btn" style="text-align: center; text-decoration: none; padding: 0.4rem 0.1rem; font-size: 0.72rem; font-weight: 600; border-radius: 6px; transition: all 0.2s; color: <?php echo $is_active ? '#fff' : 'var(--text-secondary)'; ?>; background: <?php echo $is_active ? 'var(--accent-gradient)' : 'transparent'; ?>; box-shadow: <?php echo $is_active ? '0 2px 8px rgba(99,102,241,0.3)' : 'none'; ?>;" title="<?php echo htmlspecialchars($b_name_pill); ?>">
                                <?php echo htmlspecialchars($pill_label); ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                </div>
                
                <ul class="nav-links">
                    <li class="nav-item <?php echo $current_tab === 'overview' ? 'active' : ''; ?>">
                        <a href="admin.php?tab=overview">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>
                            Dashboard
                        </a>
                    </li>
                    <li class="nav-item <?php echo $current_tab === 'redirects' ? 'active' : ''; ?>">
                        <a href="admin.php?tab=redirects">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                            Manage Links
                        </a>
                    </li>
                    <li class="nav-item <?php echo $current_tab === 'domains' ? 'active' : ''; ?>">
                        <a href="admin.php?tab=domains">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                            Domains List
                        </a>
                    </li>
                    <li class="nav-item <?php echo $current_tab === 'logs' ? 'active' : ''; ?>">
                        <a href="admin.php?tab=logs">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                            Click Logs
                        </a>
                    </li>
                    <li class="nav-item <?php echo $current_tab === 'security' ? 'active' : ''; ?>">
                        <a href="admin.php?tab=security">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            Security Settings
                        </a>
                    </li>
                    <li class="nav-item <?php echo $current_tab === 'settings' ? 'active' : ''; ?>">
                        <a href="admin.php?tab=settings">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                            General Settings
                        </a>
                    </li>
                </ul>

                <div class="user-profile">
                    <div class="profile-info">
                        <span class="profile-name"><?php echo htmlspecialchars($_SESSION['username']); ?></span>
                        <span class="profile-role"><?php echo htmlspecialchars($_SESSION['role']); ?></span>
                    </div>
                    <a href="admin.php?logout=1" class="btn-icon" title="Logout">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                    </a>
                </div>
            </aside>

            <!-- Content Area -->
            <main class="content-area">
                <?php if ($success): ?>
                    <div class="alert alert-success">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                        <span><?php echo htmlspecialchars($success); ?></span>
                    </div>
                <?php endif; ?>

                <?php if ($error): ?>
                    <div class="alert alert-error">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        <span><?php echo htmlspecialchars($error); ?></span>
                    </div>
                <?php endif; ?>

                <!-- TAB: OVERVIEW -->
                <?php if ($current_tab === 'overview'): 
                    // Calculate Overview figures
                    $all_redirects_raw = $db->getRedirects($active_brand_id);
                    $total_links = count($all_redirects_raw);
                    
                    $active_links = count(array_filter($all_redirects_raw, function($r) {
                        return intval($r['status']) === 1;
                    }));
                    
                    $total_clicks = array_sum(array_column($all_redirects_raw, 'clicks'));
                    $clicks_24h = $db->getLogsCount24h($active_brand_id);
                    
                    // Fetch top 5 redirects
                    $top_redirects = $all_redirects_raw;
                    usort($top_redirects, function($a, $b) {
                        return intval($b['clicks']) <=> intval($a['clicks']);
                    });
                    $top_redirects = array_slice($top_redirects, 0, 5);
                ?>
                    <div class="stats-grid">
                        <div class="stats-card">
                            <div class="stats-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                            </div>
                            <div class="stats-info">
                                <span class="stats-title">Total Links</span>
                                <span class="stats-value"><?php echo $total_links; ?> <span style="font-size:0.85rem; font-weight:normal; color:var(--text-secondary);"> (<?php echo $active_links; ?> active)</span></span>
                            </div>
                        </div>
                        <div class="stats-card">
                            <div class="stats-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                            </div>
                            <div class="stats-info">
                                <span class="stats-title">Total Clicks</span>
                                <span class="stats-value"><?php echo number_format($total_clicks); ?></span>
                            </div>
                        </div>
                        <div class="stats-card">
                            <div class="stats-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                            </div>
                            <div class="stats-info">
                                <span class="stats-title">Clicks (Last 24h)</span>
                                <span class="stats-value"><?php echo number_format($clicks_24h); ?></span>
                            </div>
                        </div>
                    </div>

                    <div class="dashboard-grid">
                        <!-- Top Links Panel -->
                        <div class="card">
                            <h2 class="card-title" style="margin-bottom: 1.5rem;">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
                                Top Performing Links
                            </h2>
                            <div class="bar-list">
                                <?php if (empty($top_redirects) || $total_clicks === 0): ?>
                                    <p style="color: var(--text-secondary); text-align: center; padding: 2rem 0;">No clicks recorded yet.</p>
                                <?php else: 
                                    $max_clicks = max(1, $top_redirects[0]['clicks']);
                                    foreach ($top_redirects as $link): 
                                        if (intval($link['clicks']) === 0) continue;
                                        $pct = round(($link['clicks'] / $max_clicks) * 100);
                                        $link_slug = $link['slug'] === 'default' ? '/' : '/' . $link['slug'];
                                    ?>
                                        <div class="bar-item">
                                            <div class="bar-item-info">
                                                <span class="bar-slug"><?php echo htmlspecialchars($link_slug); ?></span>
                                                <span class="bar-clicks"><?php echo number_format($link['clicks']); ?> clicks</span>
                                            </div>
                                            <div class="bar-track">
                                                <div class="bar-fill" style="width: <?php echo $pct; ?>%;"></div>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- Quick actions panel -->
                        <div class="card">
                            <h2 class="card-title" style="margin-bottom: 1.25rem;">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>
                                System Actions
                            </h2>
                            <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                                <a href="admin.php?tab=redirects" class="submit-btn" style="text-decoration:none; justify-content:center;">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                                    Create New Link
                                </a>
                                <a href="admin.php?export=csv" class="action-btn" style="text-decoration:none; justify-content:center; padding: 0.8rem 1.5rem; border-radius:14px; font-weight:600;">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                    Export redirects (CSV)
                                </a>
                                <form method="POST" onsubmit="return confirm('Are you sure you want to clear all logs? This will reset all click counters.');" style="width: 100%;">
                                    <input type="hidden" name="action" value="clear_logs">
                                    <button type="submit" class="action-btn action-btn-danger" style="width: 100%; justify-content:center; padding: 0.8rem 1.5rem; border-radius:14px; font-weight:600;">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                                        Clear Click Logs
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <!-- Recent clicks logs table -->
                    <div class="card">
                        <h2 class="card-title" style="margin-bottom: 1.25rem;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
                            Recent Clicks Log
                        </h2>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Slug</th>
                                        <th>IP Address</th>
                                        <th>Device / Browser</th>
                                        <th>Referrer</th>
                                        <th>Timestamp</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php 
                                    $logs_raw = $db->getLogs($active_brand_id);
                                    usort($logs_raw, function($a, $b) {
                                        return strtotime($b['clicked_at']) <=> strtotime($a['clicked_at']);
                                    });
                                    $recent_logs = array_slice($logs_raw, 0, 5);
                                    
                                    if (empty($recent_logs)): ?>
                                        <tr>
                                            <td colspan="5" style="text-align: center; color: var(--text-secondary);">No clicks recorded yet.</td>
                                        </tr>
                                    <?php else: 
                                        foreach ($recent_logs as $log): 
                                            $r_obj = $db->getRedirectById($log['redirect_id']);
                                            $slug_display = $r_obj ? $r_obj['slug'] : 'fallback';
                                        ?>
                                            <tr>
                                                <td class="slug-url" style="color:var(--accent-primary);">/<?php echo htmlspecialchars($slug_display); ?></td>
                                                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                                <td style="font-size:0.85rem; color:var(--text-secondary);"><?php echo htmlspecialchars(parse_user_agent($log['user_agent'])); ?></td>
                                                <td style="font-size:0.85rem; color:var(--text-secondary); max-width:200px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;" title="<?php echo htmlspecialchars($log['referrer']); ?>">
                                                    <?php echo $log['referrer'] ? htmlspecialchars($log['referrer']) : '<em style="opacity:0.5;">Direct / None</em>'; ?>
                                                </td>
                                                <td style="font-size:0.85rem; color:var(--text-secondary);"><?php echo $log['clicked_at']; ?></td>
                                            </tr>
                                        <?php endforeach; 
                                    endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- TAB: REDIRECTS -->
                <?php if ($current_tab === 'redirects'): 
                    $redirects = $db->getRedirects($active_brand_id);
                    usort($redirects, function($a, $b) {
                        return intval($b['id']) <=> intval($a['id']);
                    });
                ?>
                    <div class="card-header-actions">
                        <h2 class="card-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                            Manage Redirections
                        </h2>
                        <button type="button" class="submit-btn" onclick="openAddModal()">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                            Create Link
                        </button>
                    </div>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Link Path / Slug</th>
                                    <th>Target Destination</th>
                                    <th>Status</th>
                                    <th>Total Clicks</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($redirects)): ?>
                                    <tr>
                                        <td colspan="5" style="text-align: center; color: var(--text-secondary);">No redirection links configured yet.</td>
                                    </tr>
                                <?php else: 
                                    foreach ($redirects as $link): 
                                        $visitor_url = $domain_url . ($link['slug'] === 'default' ? '' : $link['slug']);
                                    ?>
                                        <tr>
                                            <td>
                                                <div class="slug-url">/<?php echo htmlspecialchars($link['slug']); ?></div>
                                                <div style="font-size: 0.75rem; color: var(--text-secondary); display:flex; align-items:center; gap:0.4rem; margin-top:0.25rem;">
                                                    <span id="url-text-<?php echo $link['id']; ?>"><?php echo htmlspecialchars($visitor_url); ?></span>
                                                    <button type="button" class="btn-icon" style="padding:0.15rem; color:var(--accent-primary);" onclick="copyLink('url-text-<?php echo $link['id']; ?>')" title="Copy to clipboard">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                                    </button>
                                                </div>
                                            </td>
                                            <td>
                                                <div class="target-url"><?php echo htmlspecialchars($link['target_url']); ?></div>
                                            </td>
                                            <td>
                                                <span class="badge <?php echo $link['status'] ? 'badge-active' : 'badge-inactive'; ?>">
                                                    <?php echo $link['status'] ? 'Active' : 'Inactive'; ?>
                                                </span>
                                            </td>
                                            <td style="font-family: monospace; font-size: 1rem; font-weight:600;">
                                                <?php echo number_format($link['clicks']); ?>
                                            </td>
                                            <td>
                                                <div class="actions-cell">
                                                    <button type="button" class="action-btn" onclick="openEditModal(<?php echo htmlspecialchars(json_encode($link)); ?>)">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
                                                        Edit
                                                    </button>
                                                    <?php if ($link['slug'] !== 'default'): ?>
                                                        <a href="admin.php?tab=redirects&delete_link=<?php echo $link['id']; ?>" class="action-btn action-btn-danger" onclick="return confirm('Are you sure you want to delete this link? Click history for this slug will be lost.');">
                                                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                                                            Delete
                                                        </a>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; 
                                endif; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>

                <!-- TAB: DOMAINS LIST -->
                <?php if ($current_tab === 'domains'): 
                    $domains = $db->getDomains($active_brand_id);
                    usort($domains, function($a, $b) {
                        return intval($a['id']) <=> intval($b['id']);
                    });
                ?>
                    <div class="card-header-actions">
                        <h2 class="card-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                            Domain Rotation Manager
                        </h2>
                        <div style="display:flex; gap:0.5rem;">
                            <a href="admin.php?tab=domains&check_domains=1" class="action-btn" style="text-decoration:none; background:var(--accent-gradient); color:white; border:none; box-shadow:0 4px 10px rgba(99,102,241,0.2);">
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
                                Check Domains Now
                            </a>
                            <a href="admin.php?tab=domains&rotate_domain=1" class="action-btn" style="text-decoration:none;" onclick="return confirm('Are you sure you want to manually force-rotate to the next domain?');">
                                Force Rotate Active Domain
                            </a>
                        </div>
                    </div>

                    <!-- Add domain card -->
                    <div class="card" style="max-width:550px;">
                        <h3 class="card-title" style="font-size:1.1rem; margin-bottom:1rem;">Add Backup Domain</h3>
                        <form method="POST">
                            <input type="hidden" name="action" value="add_domain">
                            <div class="form-group" style="margin-bottom:1rem;">
                                <label for="new_domain">Domain Hostname</label>
                                <div class="input-wrapper">
                                    <input type="text" name="new_domain" id="new_domain" class="form-input" placeholder="e.g. backup-domain.com" required>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line></svg>
                                </div>
                            </div>
                            <button type="submit" class="submit-btn" style="padding: 0.6rem 1.5rem; font-size:0.85rem;">Add Domain</button>
                        </form>
                    </div>

                    <!-- Domains Table -->
                    <div class="card">
                        <h3 class="card-title" style="font-size:1.1rem; margin-bottom:1.5rem;">Configured Domains</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Domain Hostname</th>
                                        <th>Status</th>
                                        <th>Last Checked</th>
                                        <th>Block Reason</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($domains as $d): ?>
                                        <tr>
                                            <td style="font-weight:600; font-size:1rem; font-family:monospace;"><?php echo htmlspecialchars($d['domain']); ?></td>
                                            <td>
                                                <?php if ($d['status'] === 'active'): ?>
                                                    <span class="badge" style="background:var(--accent-gradient); color:white; border:none; box-shadow:0 2px 8px rgba(99,102,241,0.2);">ACTIVE TRAFFIC</span>
                                                <?php elseif ($d['status'] === 'clean'): ?>
                                                    <span class="badge badge-active">CLEAN BACKUP</span>
                                                <?php else: ?>
                                                    <span class="badge badge-inactive">BLOCKED</span>
                                                <?php endif; ?>
                                            </td>
                                            <td style="font-size:0.85rem; color:var(--text-secondary);"><?php echo $d['last_checked']; ?></td>
                                            <td style="font-size:0.85rem; color:var(--error-color); max-width:200px; word-break:break-word; font-weight:500;">
                                                <?php echo $d['blocked_reason'] ? htmlspecialchars($d['blocked_reason']) : '<span style="opacity:0.3; color:var(--text-secondary);">-</span>'; ?>
                                            </td>
                                            <td>
                                                <div class="actions-cell">
                                                    <?php if ($d['status'] !== 'active'): ?>
                                                        <a href="admin.php?tab=domains&delete_domain=<?php echo $d['id']; ?>" class="action-btn action-btn-danger" style="padding:0.4rem 0.6rem; font-size:0.75rem;" onclick="return confirm('Are you sure you want to delete this domain?');">Delete</a>
                                                    <?php else: ?>
                                                        <span style="font-size:0.75rem; color:var(--text-secondary); font-style:italic;">Active (Primary)</span>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- TAB: CLICK LOGS -->
                <?php if ($current_tab === 'logs'): 
                    $filter_slug = $_GET['filter_slug'] ?? '';
                    $filter_ip = $_GET['filter_ip'] ?? '';
                    
                    $all_logs = $db->getLogs($active_brand_id);
                    usort($all_logs, function($a, $b) {
                        return strtotime($b['clicked_at']) <=> strtotime($a['clicked_at']);
                    });
                    
                    $filtered_logs = [];
                    foreach ($all_logs as $log) {
                        $r = $db->getRedirectById($log['redirect_id']);
                        $slug_val = $r ? $r['slug'] : 'fallback';
                        
                        if (!empty($filter_slug) && $slug_val !== $filter_slug) continue;
                        if (!empty($filter_ip) && stripos($log['ip_address'], $filter_ip) === false) continue;
                        
                        $log['slug'] = $slug_val;
                        $filtered_logs[] = $log;
                    }
                    $logs = array_slice($filtered_logs, 0, 100);
                    
                    // Fetch list of slugs for filter select
                    $all_slugs_list = $db->getRedirects($active_brand_id);
                    usort($all_slugs_list, function($a, $b) {
                        return strcmp($a['slug'], $b['slug']);
                    });
                ?>
                    <div class="card-header-actions">
                        <h2 class="card-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                            Visitor Click Logs
                        </h2>
                    </div>

                    <div class="card">
                        <form method="GET" class="filter-header" style="margin-bottom: 0;">
                            <input type="hidden" name="tab" value="logs">
                            
                            <div style="display:flex; gap:1rem; flex-wrap:wrap; flex-grow:1;">
                                <div class="form-group" style="margin-bottom:0; min-width:200px;">
                                    <div class="input-wrapper">
                                        <select name="filter_slug" class="form-select" style="padding: 0.6rem 1rem 0.6rem 2.25rem;">
                                            <option value="">-- Filter by Link Slug --</option>
                                            <?php foreach ($all_slugs_list as $sl): ?>
                                                <option value="<?php echo htmlspecialchars($sl['slug']); ?>" <?php echo $filter_slug === $sl['slug'] ? 'selected' : ''; ?>>/<?php echo htmlspecialchars($sl['slug']); ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                                    </div>
                                </div>
                                
                                <div class="form-group" style="margin-bottom:0; min-width:200px;">
                                    <div class="input-wrapper">
                                        <input type="text" name="filter_ip" class="form-input" placeholder="Filter by IP address" value="<?php echo htmlspecialchars($filter_ip); ?>" style="padding: 0.6rem 1rem 0.6rem 2.25rem;">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                                    </div>
                                </div>
                            </div>
                            
                            <div style="display:flex; gap:0.5rem; align-items:center;">
                                <button type="submit" class="submit-btn" style="padding: 0.6rem 1.5rem; font-size:0.85rem;">Apply Filters</button>
                                <?php if (!empty($filter_slug) || !empty($filter_ip)): ?>
                                    <a href="admin.php?tab=logs" class="action-btn" style="padding: 0.6rem 1.2rem; text-decoration:none;">Reset</a>
                                <?php endif; ?>
                            </div>
                        </form>
                    </div>

                    <div class="card">
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Slug</th>
                                        <th>IP Address</th>
                                        <th>Device / User Agent</th>
                                        <th>Referrer</th>
                                        <th>Date</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($logs)): ?>
                                        <tr>
                                            <td colspan="5" style="text-align: center; color: var(--text-secondary);">No logs found matching your criteria.</td>
                                        </tr>
                                    <?php else: 
                                        foreach ($logs as $log): ?>
                                            <tr>
                                                <td class="slug-url" style="color:var(--accent-primary);">/<?php echo htmlspecialchars($log['slug'] ?? 'fallback'); ?></td>
                                                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                                <td style="font-size:0.85rem; color:var(--text-secondary);" title="<?php echo htmlspecialchars($log['user_agent']); ?>">
                                                    <?php echo htmlspecialchars(parse_user_agent($log['user_agent'])); ?>
                                                </td>
                                                <td style="font-size:0.85rem; color:var(--text-secondary); max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="<?php echo htmlspecialchars($log['referrer']); ?>">
                                                    <?php echo $log['referrer'] ? htmlspecialchars($log['referrer']) : '<em style="opacity:0.5;">Direct / None</em>'; ?>
                                                </td>
                                                <td style="font-size:0.85rem; color:var(--text-secondary);"><?php echo $log['clicked_at']; ?></td>
                                            </tr>
                                        <?php endforeach; 
                                    endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- TAB: SECURITY -->
                <?php if ($current_tab === 'security'): 
                    $users = $db->getUsers();
                    usort($users, function($a, $b) {
                        return intval($a['id']) <=> intval($b['id']);
                    });
                ?>
                    <div class="card-header-actions">
                        <h2 class="card-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            Security & Credentials
                        </h2>
                    </div>

                    <div class="dashboard-grid">
                        <!-- Update password and recovery question -->
                        <div class="card">
                            <h3 class="card-title" style="margin-bottom: 1.5rem; border-bottom:1px solid var(--border-color); padding-bottom:0.75rem;">Update Security profile</h3>
                            <form method="POST">
                                <input type="hidden" name="action" value="security_update">
                                
                                <div class="form-group">
                                    <label for="current_password">Current Password (Required)</label>
                                    <div class="input-wrapper">
                                        <input type="password" name="current_password" id="current_password" class="form-input" required>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                    </div>
                                </div>

                                <div style="border-top:1px solid var(--border-color); padding-top:1.5rem; margin-top:1.5rem; margin-bottom:1rem;">
                                    <h4 style="font-size:0.9rem; font-weight:600; text-transform:uppercase; color:var(--text-secondary); margin-bottom:1rem;">Change Password (optional)</h4>
                                </div>

                                <div class="form-group">
                                    <label for="new_password">New Password</label>
                                    <div class="input-wrapper">
                                        <input type="password" name="new_password" id="new_password" class="form-input" placeholder="Leave blank to keep current">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label for="confirm_new">Confirm New Password</label>
                                    <div class="input-wrapper">
                                        <input type="password" name="confirm_new" id="confirm_new" class="form-input" placeholder="Leave blank to keep current">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                    </div>
                                </div>

                                <div style="border-top:1px solid var(--border-color); padding-top:1.5rem; margin-top:1.5rem; margin-bottom:1rem;">
                                    <h4 style="font-size:0.9rem; font-weight:600; text-transform:uppercase; color:var(--text-secondary); margin-bottom:1rem;">Recovery Question (optional)</h4>
                                </div>

                                <div class="form-group">
                                    <label for="security_question">Security Recovery Question</label>
                                    <div class="input-wrapper">
                                        <select name="security_question" id="security_question" class="form-select">
                                            <option value="">-- Keep Current Question --</option>
                                            <option value="What is the name of your first school?">What is the name of your first school?</option>
                                            <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                                            <option value="What city were you born in?">What city were you born in?</option>
                                            <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
                                            <option value="What was the model of your first car?">What was the model of your first car?</option>
                                        </select>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path></svg>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label for="security_answer">New Answer</label>
                                    <div class="input-wrapper">
                                        <input type="text" name="security_answer" id="security_answer" class="form-input" placeholder="Provide answer if updating recovery question">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><key>🔑</key><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.778-7.778zM12 5.79l7.21 7.21M17 11l-3 3M19 9l-3 3"></path></svg>
                                    </div>
                                </div>

                                <button type="submit" class="submit-btn" style="width: auto;">Update Security</button>
                            </form>
                        </div>

                        <!-- User Management (Admins only) -->
                        <div class="card">
                            <h3 class="card-title" style="margin-bottom: 1.5rem; border-bottom:1px solid var(--border-color); padding-bottom:0.75rem;">System Accounts</h3>
                            
                            <?php if ($_SESSION['role'] !== 'admin'): ?>
                                <p style="color: var(--text-secondary); font-size: 0.9rem;">Operator accounts do not have permission to manage other users.</p>
                            <?php else: ?>
                                <!-- Add User Form -->
                                <form method="POST" style="margin-bottom: 2rem; border-bottom: 1px solid var(--border-color); padding-bottom:1.5rem;">
                                    <input type="hidden" name="action" value="add_user">
                                    <h4 style="font-size:0.85rem; font-weight:600; text-transform:uppercase; color:var(--text-secondary); margin-bottom:1rem;">Add New User</h4>
                                    
                                    <div class="form-group">
                                        <label for="add_username">Username</label>
                                        <div class="input-wrapper">
                                            <input type="text" name="username" id="add_username" class="form-input" style="padding: 0.6rem 1rem 0.6rem 2.5rem;" required>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                                        </div>
                                    </div>

                                    <div class="form-group">
                                        <label for="add_password">Password</label>
                                        <div class="input-wrapper">
                                            <input type="password" name="password" id="add_password" class="form-input" style="padding: 0.6rem 1rem 0.6rem 2.5rem;" required>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                        </div>
                                    </div>

                                    <div class="form-group">
                                        <label for="add_role">Role</label>
                                        <div class="input-wrapper">
                                            <select name="role" id="add_role" class="form-select" style="padding: 0.6rem 1rem 0.6rem 2.5rem;" required>
                                                <option value="operator">Operator (Manage links only)</option>
                                                <option value="admin">Administrator (Full Access)</option>
                                            </select>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                                        </div>
                                    </div>

                                    <button type="submit" class="submit-btn" style="padding: 0.6rem 1.5rem; font-size:0.85rem;">Create Account</button>
                                </form>

                                <!-- Users Table -->
                                <h4 style="font-size:0.85rem; font-weight:600; text-transform:uppercase; color:var(--text-secondary); margin-bottom:1rem;">User List</h4>
                                <div class="table-container">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>User</th>
                                                <th>Role</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($users as $u): ?>
                                                <tr>
                                                    <td style="font-weight: 600;"><?php echo htmlspecialchars($u['username']); ?></td>
                                                    <td>
                                                        <span class="badge" style="background:rgba(255,255,255,0.05); color:var(--text-primary); border:1px solid var(--border-color);">
                                                            <?php echo strtoupper($u['role']); ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <?php if ($u['id'] !== $_SESSION['user_id']): ?>
                                                            <a href="admin.php?tab=security&delete_user=<?php echo $u['id']; ?>" class="action-btn action-btn-danger" style="padding: 0.35rem 0.6rem; font-size:0.75rem;" onclick="return confirm('Are you sure you want to delete this user?');">Delete</a>
                                                        <?php else: ?>
                                                            <span style="font-size:0.75rem; color:var(--text-secondary); font-style:italic;">You</span>
                                                        <?php endif; ?>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- TAB: SETTINGS -->
                <?php if ($current_tab === 'settings'): ?>
                    <div class="card-header-actions">
                        <h2 class="card-title">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                            General Settings
                        </h2>
                    </div>

                    <div class="card" style="max-width: 650px;">
                        <form method="POST">
                            <input type="hidden" name="action" value="save_settings">
                            
                            <!-- Brand settings section -->
                            <div style="border-bottom:1px solid var(--border-color); padding-bottom:0.75rem; margin-bottom:1.5rem;">
                                <h4 style="font-size:0.9rem; font-weight:600; text-transform:uppercase; color:var(--text-secondary); margin-bottom:0.25rem;">Brand settings (<?php echo htmlspecialchars($brand_name); ?>)</h4>
                                <span style="font-size:0.75rem; color:var(--text-secondary);">These settings only apply to the currently selected brand.</span>
                            </div>

                            <div class="form-group">
                                <label for="brand_name">Brand Name</label>
                                <div class="input-wrapper">
                                    <input type="text" name="brand_name" id="brand_name" class="form-input" value="<?php echo htmlspecialchars($brand_name); ?>" placeholder="e.g. Wings365" required>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
                                </div>
                                <span style="font-size:0.8rem; color:var(--text-secondary); display:block; margin-top:0.4rem;">The display name for the currently selected brand.</span>
                            </div>

                            <div class="form-group">
                                <label for="fallback_url">Brand Fallback URL</label>
                                <div class="input-wrapper">
                                    <input type="text" name="fallback_url" id="fallback_url" class="form-input" value="<?php echo htmlspecialchars($fallback_url); ?>" placeholder="https://cutt.ly/002wings" required>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                                </div>
                                <span style="font-size:0.8rem; color:var(--text-secondary); display:block; margin-top:0.4rem;">Used as a backup redirection target when an requested slug does not match any entry, and no default redirect exists for this brand.</span>
                            </div>

                            <div class="form-group" style="margin-top: 2rem;">
                                <label for="domain_override">Brand Domain Override (Optional)</label>
                                <div class="input-wrapper">
                                    <input type="text" name="domain_override" id="domain_override" class="form-input" value="<?php echo htmlspecialchars($domain_override); ?>" placeholder="e.g. https://wingsinformation.com">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                                </div>
                                <span style="font-size:0.8rem; color:var(--text-secondary); display:block; margin-top:0.4rem;">If set, copies of link paths on the dashboard for this brand will use this URL instead of dynamically detecting the host header. Include the protocol (<code>http://</code> or <code>https://</code>) but do not include a trailing slash.</span>
                            </div>

                            <div style="border-top:1px solid var(--border-color); padding-top:1.5rem; margin-top:2rem; margin-bottom:1rem;">
                                <h4 style="font-size:0.9rem; font-weight:600; text-transform:uppercase; color:var(--text-secondary); margin-bottom:0.25rem;">Global Configuration</h4>
                                <span style="font-size:0.75rem; color:var(--text-secondary); margin-bottom:1rem; display:block;">These settings apply to all 4 brands across the entire system.</span>
                            </div>

                            <div class="form-group">
                                <label for="safe_browsing_key">Google Safe Browsing API Key (Optional)</label>
                                <div class="input-wrapper">
                                    <input type="text" name="safe_browsing_key" id="safe_browsing_key" class="form-input" value="<?php echo htmlspecialchars($safe_browsing_key); ?>" placeholder="Enter API Key">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                </div>
                                <span style="font-size:0.8rem; color:var(--text-secondary); display:block; margin-top:0.4rem;">Provides secondary verification for malware/phishing warnings. If left blank, the checker will rely on DNS-based spam databases (SURBL/Spamhaus) which work out-of-the-box.</span>
                            </div>

                            <div class="form-group">
                                <label for="check_interval_hours">Checking Interval (Hours)</label>
                                <div class="input-wrapper">
                                    <input type="number" name="check_interval_hours" id="check_interval_hours" class="form-input" value="<?php echo $check_interval_hours; ?>" min="0.01" step="0.01" required>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                                </div>
                                <span style="font-size:0.8rem; color:var(--text-secondary); display:block; margin-top:0.4rem;">How often the system scans the active domain for blocks (default: every 6 hours). You can use decimals (e.g. <code>0.5</code> for 30 minutes, <code>0.25</code> for 15 minutes). Checked periodically during visitor redirects.</span>
                            </div>

                            <button type="submit" class="submit-btn" style="margin-top: 1.5rem;">Save Settings</button>
                        </form>
                    </div>
                <?php endif; ?>
            </main>
        </div>
    <?php endif; ?>

    <!-- Modal Elements for Add/Edit Link -->
    <?php if ($is_authenticated && $current_tab === 'redirects'): ?>
        <div class="modal-overlay" id="link-modal">
            <div class="modal-card">
                <h3 class="card-title" id="modal-title" style="margin-bottom:1.5rem; border-bottom:1px solid var(--border-color); padding-bottom:0.75rem;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    <span>Create Redirection Link</span>
                </h3>
                <form method="POST" id="modal-form" onsubmit="return validateModalForm()">
                    <input type="hidden" name="action" id="modal-action" value="add_link">
                    <input type="hidden" name="id" id="modal-id" value="">
                    
                    <div class="form-group">
                        <label for="modal-slug">URL Slug / Path</label>
                        <div class="input-wrapper">
                            <input type="text" name="slug" id="modal-slug" class="form-input" placeholder="e.g. promo" required>
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path><rect x="2" y="9" width="4" height="12"></rect><circle cx="4" cy="4" r="2"></circle></svg>
                        </div>
                        <span style="font-size:0.75rem; color:var(--text-secondary); display:block; margin-top:0.35rem;">Use lowercase letters, numbers, and dashes. Use "<code>default</code>" to override root domain redirection.</span>
                    </div>

                    <div class="form-group">
                        <label for="modal-target">Target Redirect URL</label>
                        <div class="input-wrapper">
                            <input type="text" name="target_url" id="modal-target" class="form-input" placeholder="https://example.com/landing-page" required>
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                        </div>
                        <div id="modal-url-validation" style="color:var(--error-color); font-size:0.75rem; display:none; margin-top:0.35rem;">Include a valid protocol (http:// or https://) in the URL.</div>
                    </div>

                    <div class="form-group" style="margin-top:1.5rem; margin-bottom:1.5rem;">
                        <label class="checkbox-container">
                            <input type="checkbox" name="status" id="modal-status" checked>
                            <span class="checkbox-checkmark">
                                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                            </span>
                            Active Status (Visitors will be redirected when enabled)
                        </label>
                    </div>

                    <div class="modal-footer">
                        <button type="button" class="submit-btn btn-secondary" onclick="closeModal()">Cancel</button>
                        <button type="submit" class="submit-btn" id="modal-submit-label">Create Link</button>
                    </div>
                </form>
            </div>
        </div>
    <?php endif; ?>

    <footer>
        Wings365 console &copy; 2026. JSON safe local storage active.
    </footer>

    <script>
        function copyLink(elementId) {
            var urlText = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(urlText).then(function() {
                var toast = document.getElementById("toast-copy");
                toast.classList.add("active");
                
                setTimeout(function() {
                    toast.classList.remove("active");
                }, 2000);
            }, function(err) {
                console.error('Could not copy link: ', err);
            });
        }

        // Modal triggers
        function openAddModal() {
            document.getElementById("modal-title").querySelector("span").innerText = "Create Redirection Link";
            document.getElementById("modal-submit-label").innerText = "Create Link";
            document.getElementById("modal-action").value = "add_link";
            document.getElementById("modal-id").value = "";
            document.getElementById("modal-slug").value = "";
            document.getElementById("modal-slug").removeAttribute("readonly");
            document.getElementById("modal-target").value = "";
            document.getElementById("modal-status").checked = true;
            
            document.getElementById("link-modal").classList.add("active");
        }

        function openEditModal(linkData) {
            document.getElementById("modal-title").querySelector("span").innerText = "Edit Redirection Link";
            document.getElementById("modal-submit-label").innerText = "Save Changes";
            document.getElementById("modal-action").value = "edit_link";
            document.getElementById("modal-id").value = linkData.id;
            document.getElementById("modal-slug").value = linkData.slug;
            
            // Default slug should not be renamed to maintain fallback routing
            if (linkData.slug === 'default') {
                document.getElementById("modal-slug").setAttribute("readonly", "readonly");
            } else {
                document.getElementById("modal-slug").removeAttribute("readonly");
            }
            
            document.getElementById("modal-target").value = linkData.target_url;
            document.getElementById("modal-status").checked = parseInt(linkData.status) === 1;
            
            document.getElementById("link-modal").classList.add("active");
        }

        function closeModal() {
            document.getElementById("link-modal").classList.remove("active");
            document.getElementById("modal-url-validation").style.display = "none";
        }

        function validateModalForm() {
            var targetInput = document.getElementById("modal-target").value.trim();
            var errorDiv = document.getElementById("modal-url-validation");
            
            try {
                var url = new URL(targetInput);
                if (url.protocol === "http:" || url.protocol === "https:") {
                    errorDiv.style.display = "none";
                    return true;
                }
            } catch (_) {
                // Fail logic
            }
            
            errorDiv.style.display = "block";
            return false;
        }
    </script>
</body>
</html>
