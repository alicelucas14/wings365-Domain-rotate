<?php
// Secure JSON Database Helper with Concurrent File Locking

class JsonDatabase {
    private $db_file;
    private $data;

    public function __construct() {
        $db_dir = __DIR__ . '/data';
        $this->db_file = $db_dir . '/database.json';
        
        if (!file_exists($db_dir)) {
            mkdir($db_dir, 0755, true);
        }
        
        // Initialize if file doesn't exist
        if (!file_exists($this->db_file)) {
            $this->update_db(function($data) {
                return $data; // Returns default initialized structure
            });
        } else {
            $this->load();
        }

        // Auto-initialize current hostname as active domain if list is empty
        if ($this->getUserCount() > 0 && count($this->getDomains()) === 0 && isset($_SERVER['HTTP_HOST'])) {
            $this->addDomain($_SERVER['HTTP_HOST']);
        }
    }

    // Load data from file with shared lock
    private function load() {
        $fp = fopen($this->db_file, 'r');
        if ($fp) {
            flock($fp, LOCK_SH);
            $size = filesize($this->db_file);
            $content = $size > 0 ? fread($fp, $size) : '';
            flock($fp, LOCK_UN);
            fclose($fp);
            $this->data = json_decode($content, true);
        }
        
        if (!is_array($this->data)) {
            $this->data = [
                'users' => [],
                'redirects' => [],
                'click_logs' => [],
                'domains' => [],
                'settings' => [
                    'fallback_url' => 'https://cutt.ly/002wings',
                    'domain_override' => '',
                    'safe_browsing_key' => '',
                    'check_interval_hours' => 6
                ]
            ];
        }

        // Backwards compatibility safety checks
        if (!isset($this->data['domains'])) {
            $this->data['domains'] = [];
        }
        if (!isset($this->data['settings']['safe_browsing_key'])) {
            $this->data['settings']['safe_browsing_key'] = '';
        }
        if (!isset($this->data['settings']['check_interval_hours'])) {
            $this->data['settings']['check_interval_hours'] = 6;
        }
    }

    // Safely update database under exclusive lock to prevent race conditions
    private function update_db($callback) {
        $fp = fopen($this->db_file, 'c+'); // Open for reading and writing
        if ($fp) {
            flock($fp, LOCK_EX); // Acquire exclusive lock
            
            // Read fresh content from disk
            clearstatcache();
            $size = filesize($this->db_file);
            $content = '';
            if ($size > 0) {
                rewind($fp);
                $content = fread($fp, $size);
            }
            
            $data = json_decode($content, true);
            if (!is_array($data)) {
                $data = [
                    'users' => [],
                    'redirects' => [],
                    'click_logs' => [],
                    'domains' => [],
                    'settings' => [
                        'fallback_url' => 'https://cutt.ly/002wings',
                        'domain_override' => '',
                        'safe_browsing_key' => '',
                        'check_interval_hours' => 6
                    ]
                ];
            }

            if (!isset($data['domains'])) {
                $data['domains'] = [];
            }
            if (!isset($data['settings']['safe_browsing_key'])) {
                $data['settings']['safe_browsing_key'] = '';
            }
            if (!isset($data['settings']['check_interval_hours'])) {
                $data['settings']['check_interval_hours'] = 6;
            }
            
            // Run modification callback
            $data = $callback($data);
            
            // Write back
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
            fflush($fp);
            
            flock($fp, LOCK_UN); // Release lock
            fclose($fp);
            
            $this->data = $data;
            return true;
        }
        return false;
    }

    // ----------------------------------------------------
    // USER METHODS
    // ----------------------------------------------------
    public function getUserCount() {
        $this->load();
        return count($this->data['users']);
    }

    public function getUsers() {
        $this->load();
        return $this->data['users'];
    }

    public function getUserByUsername($username) {
        $this->load();
        $username = strtolower(trim($username));
        foreach ($this->data['users'] as $user) {
            if (strtolower($user['username']) === $username) {
                return $user;
            }
        }
        return null;
    }

    public function getUserById($id) {
        $this->load();
        foreach ($this->data['users'] as $user) {
            if (intval($user['id']) === intval($id)) {
                return $user;
            }
        }
        return null;
    }

    public function addUser($username, $password_hash, $question = '', $answer_hash = '', $role = 'admin') {
        $id = time() . rand(100, 999);
        $this->update_db(function($data) use ($id, $username, $password_hash, $question, $answer_hash, $role) {
            $data['users'][] = [
                'id' => intval($id),
                'username' => trim($username),
                'password_hash' => $password_hash,
                'security_question' => $question,
                'security_answer_hash' => $answer_hash,
                'role' => $role,
                'created_at' => date('Y-m-d H:i:s')
            ];
            return $data;
        });
        return $id;
    }

    public function deleteUser($id) {
        return $this->update_db(function($data) use ($id) {
            foreach ($data['users'] as $key => $user) {
                if (intval($user['id']) === intval($id)) {
                    unset($data['users'][$key]);
                    $data['users'] = array_values($data['users']);
                    break;
                }
            }
            return $data;
        });
    }

    public function updateUserPassword($id, $hash) {
        return $this->update_db(function($data) use ($id, $hash) {
            foreach ($data['users'] as &$user) {
                if (intval($user['id']) === intval($id)) {
                    $user['password_hash'] = $hash;
                    break;
                }
            }
            return $data;
        });
    }

    public function updateUserSecurity($id, $q, $ans_hash) {
        return $this->update_db(function($data) use ($id, $q, $ans_hash) {
            foreach ($data['users'] as &$user) {
                if (intval($user['id']) === intval($id)) {
                    $user['security_question'] = $q;
                    $user['security_answer_hash'] = $ans_hash;
                    break;
                }
            }
            return $data;
        });
    }

    // ----------------------------------------------------
    // REDIRECT METHODS
    // ----------------------------------------------------
    public function getRedirects() {
        $this->load();
        return $this->data['redirects'];
    }

    public function getRedirectBySlug($slug) {
        $this->load();
        $slug = strtolower(trim($slug));
        foreach ($this->data['redirects'] as $r) {
            if (strtolower($r['slug']) === $slug) {
                return $r;
            }
        }
        return null;
    }

    public function getRedirectById($id) {
        $this->load();
        foreach ($this->data['redirects'] as $r) {
            if (intval($r['id']) === intval($id)) {
                return $r;
            }
        }
        return null;
    }

    public function addRedirect($slug, $target_url, $status = 1) {
        $id = time() . rand(100, 999);
        $this->update_db(function($data) use ($id, $slug, $target_url, $status) {
            $data['redirects'][] = [
                'id' => intval($id),
                'slug' => strtolower(trim($slug)),
                'target_url' => trim($target_url),
                'status' => intval($status),
                'clicks' => 0,
                'created_at' => date('Y-m-d H:i:s')
            ];
            return $data;
        });
        return $id;
    }

    public function updateRedirect($id, $slug, $target_url, $status) {
        return $this->update_db(function($data) use ($id, $slug, $target_url, $status) {
            foreach ($data['redirects'] as &$r) {
                if (intval($r['id']) === intval($id)) {
                    $r['slug'] = strtolower(trim($slug));
                    $r['target_url'] = trim($target_url);
                    $r['status'] = intval($status);
                    break;
                }
            }
            return $data;
        });
    }

    public function deleteRedirect($id) {
        return $this->update_db(function($data) use ($id) {
            foreach ($data['redirects'] as $key => $r) {
                if (intval($r['id']) === intval($id)) {
                    unset($data['redirects'][$key]);
                    $data['redirects'] = array_values($data['redirects']);
                    
                    // Cascade delete logs
                    foreach ($data['click_logs'] as $log_key => $log) {
                        if (intval($log['redirect_id']) === intval($id)) {
                            unset($data['click_logs'][$log_key]);
                        }
                    }
                    $data['click_logs'] = array_values($data['click_logs']);
                    break;
                }
            }
            return $data;
        });
    }

    public function incrementClicks($id) {
        return $this->update_db(function($data) use ($id) {
            foreach ($data['redirects'] as &$r) {
                if (intval($r['id']) === intval($id)) {
                    $r['clicks'] = intval($r['clicks']) + 1;
                    break;
                }
            }
            return $data;
        });
    }

    // ----------------------------------------------------
    // CLICK LOG METHODS
    // ----------------------------------------------------
    public function getLogs() {
        $this->load();
        return $this->data['click_logs'];
    }

    public function addClickLog($redirect_id, $ip, $ua, $ref) {
        return $this->update_db(function($data) use ($redirect_id, $ip, $ua, $ref) {
            $data['click_logs'][] = [
                'id' => time() . rand(100, 999),
                'redirect_id' => intval($redirect_id),
                'ip_address' => $ip,
                'user_agent' => $ua,
                'referrer' => $ref,
                'clicked_at' => date('Y-m-d H:i:s')
            ];
            return $data;
        });
    }

    public function clearLogs() {
        return $this->update_db(function($data) {
            $data['click_logs'] = [];
            foreach ($data['redirects'] as &$r) {
                $r['clicks'] = 0;
            }
            return $data;
        });
    }

    public function getLogsCount24h() {
        $this->load();
        $count = 0;
        $now = time();
        foreach ($this->data['click_logs'] as $log) {
            $logged_time = strtotime($log['clicked_at']);
            if (($now - $logged_time) <= 86400) {
                $count++;
            }
        }
        return $count;
    }

    // ----------------------------------------------------
    // DOMAIN ROTATION METHODS
    // ----------------------------------------------------
    public function getDomains() {
        $this->load();
        return $this->data['domains'];
    }

    public function getDomainById($id) {
        $this->load();
        foreach ($this->data['domains'] as $d) {
            if (intval($d['id']) === intval($id)) {
                return $d;
            }
        }
        return null;
    }

    public function addDomain($domain) {
        $domain = strtolower(trim(preg_replace('/^https?:\/\//i', '', $domain)));
        $domain = rtrim($domain, '/');
        
        if (empty($domain)) return false;
        
        // Check if domain already exists
        foreach ($this->getDomains() as $d) {
            if ($d['domain'] === $domain) {
                return false;
            }
        }

        $id = time() . rand(100, 999);
        
        return $this->update_db(function($data) use ($id, $domain) {
            // Check if there is already an active domain
            $has_active = false;
            foreach ($data['domains'] as $d) {
                if ($d['status'] === 'active') {
                    $has_active = true;
                    break;
                }
            }
            
            $status = $has_active ? 'clean' : 'active';
            
            $data['domains'][] = [
                'id' => intval($id),
                'domain' => $domain,
                'status' => $status,
                'last_checked' => 'Never',
                'blocked_reason' => '',
                'created_at' => date('Y-m-d H:i:s')
            ];
            return $data;
        });
    }

    public function deleteDomain($id) {
        return $this->update_db(function($data) use ($id) {
            $deleted_active = false;
            foreach ($data['domains'] as $key => $d) {
                if (intval($d['id']) === intval($id)) {
                    if ($d['status'] === 'active') {
                        $deleted_active = true;
                    }
                    unset($data['domains'][$key]);
                    $data['domains'] = array_values($data['domains']);
                    break;
                }
            }
            
            // If the active domain was deleted, activate the next clean one
            if ($deleted_active && !empty($data['domains'])) {
                foreach ($data['domains'] as &$d) {
                    if ($d['status'] === 'clean') {
                        $d['status'] = 'active';
                        break;
                    }
                }
            }
            return $data;
        });
    }

    public function getActiveDomain() {
        $this->load();
        
        // Find active domain
        foreach ($this->data['domains'] as $d) {
            if ($d['status'] === 'active') {
                return $d['domain'];
            }
        }
        
        // Fallback: search for first clean domain and make it active
        if (!empty($this->data['domains'])) {
            $activated_domain = null;
            $this->update_db(function($data) use (&$activated_domain) {
                foreach ($data['domains'] as &$d) {
                    if ($d['status'] === 'clean') {
                        $d['status'] = 'active';
                        $activated_domain = $d['domain'];
                        break;
                    }
                }
                return $data;
            });
            if ($activated_domain) return $activated_domain;
        }
        
        // Fallback to request host
        return $_SERVER['HTTP_HOST'] ?? 'localhost:8000';
    }

    public function updateDomainStatus($id, $status, $reason = '') {
        return $this->update_db(function($data) use ($id, $status, $reason) {
            foreach ($data['domains'] as &$d) {
                if (intval($d['id']) === intval($id)) {
                    $d['status'] = $status;
                    $d['last_checked'] = date('Y-m-d H:i:s');
                    $d['blocked_reason'] = $reason;
                    break;
                }
            }
            return $data;
        });
    }

    public function rotateDomain() {
        return $this->update_db(function($data) {
            $active_key = null;
            foreach ($data['domains'] as $key => $d) {
                if ($d['status'] === 'active') {
                    $active_key = $key;
                    break;
                }
            }
            
            // Find a backup domain that is clean
            $next_clean_key = null;
            foreach ($data['domains'] as $key => $d) {
                if ($d['status'] === 'clean') {
                    $next_clean_key = $key;
                    break;
                }
            }
            
            if ($next_clean_key !== null) {
                // Mark current active as blocked
                if ($active_key !== null) {
                    $data['domains'][$active_key]['status'] = 'blocked';
                    $data['domains'][$active_key]['blocked_reason'] = 'Auto-rotated: Blocked by blacklist check.';
                    $data['domains'][$active_key]['last_checked'] = date('Y-m-d H:i:s');
                }
                
                // Activate the clean backup
                $data['domains'][$next_clean_key]['status'] = 'active';
                $data['domains'][$next_clean_key]['last_checked'] = date('Y-m-d H:i:s');
            } else {
                // No clean backup domain available!
                // Log the block but keep it active as a last resort, or do nothing
                if ($active_key !== null) {
                    $data['domains'][$active_key]['blocked_reason'] = 'Flagged as blocked, but no clean backup domains are available!';
                    $data['domains'][$active_key]['last_checked'] = date('Y-m-d H:i:s');
                }
            }
            return $data;
        });
    }

    // ----------------------------------------------------
    // SETTINGS METHODS
    // ----------------------------------------------------
    public function getSetting($key) {
        $this->load();
        return $this->data['settings'][$key] ?? '';
    }

    public function updateSetting($key, $value) {
        return $this->update_db(function($data) use ($key, $value) {
            $data['settings'][$key] = $value;
            return $data;
        });
    }
}

$db = new JsonDatabase();
?>
