<?php
// Secure JSON Database Helper with Concurrent File Locking - Multi-Brand Support

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

        // Schema migration check
        $this->migrateSchema();
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
            $this->data = $this->getDefaultDataStructure();
        }
    }

    private function getDefaultDataStructure() {
        return [
            'users' => [],
            'redirects' => [],
            'click_logs' => [],
            'domains' => [],
            'settings' => [
                'fallback_url' => 'https://cutt.ly/002wings',
                'domain_override' => '',
                'safe_browsing_key' => '',
                'check_interval_hours' => 6,
                'brands' => [
                    '1' => [
                        'name' => 'Wings365',
                        'fallback_url' => 'https://cutt.ly/002wings',
                        'domain_override' => ''
                    ],
                    '2' => [
                        'name' => 'Brand 2',
                        'fallback_url' => 'https://cutt.ly/002wings',
                        'domain_override' => ''
                    ],
                    '3' => [
                        'name' => 'Brand 3',
                        'fallback_url' => 'https://cutt.ly/002wings',
                        'domain_override' => ''
                    ],
                    '4' => [
                        'name' => 'Brand 4',
                        'fallback_url' => 'https://cutt.ly/002wings',
                        'domain_override' => ''
                    ]
                ]
            ]
        ];
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
                $data = $this->getDefaultDataStructure();
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

    // Schema Migration Helper
    private function migrateSchema() {
        $this->load();
        $needs_update = false;

        $callback = function($data) use (&$needs_update) {
            // 1. Initialize brands settings if missing
            if (!isset($data['settings']['brands'])) {
                $needs_update = true;
                $default_fallback = $data['settings']['fallback_url'] ?? 'https://cutt.ly/002wings';
                $default_override = $data['settings']['domain_override'] ?? '';
                
                $data['settings']['brands'] = [
                    '1' => [
                        'name' => 'Wings365',
                        'fallback_url' => $default_fallback,
                        'domain_override' => $default_override
                    ],
                    '2' => [
                        'name' => 'Brand 2',
                        'fallback_url' => $default_fallback,
                        'domain_override' => ''
                    ],
                    '3' => [
                        'name' => 'Brand 3',
                        'fallback_url' => $default_fallback,
                        'domain_override' => ''
                    ],
                    '4' => [
                        'name' => 'Brand 4',
                        'fallback_url' => $default_fallback,
                        'domain_override' => ''
                    ]
                ];
            }

            // 2. Ensure all existing redirects have brand_id
            foreach ($data['redirects'] as &$r) {
                if (!isset($r['brand_id'])) {
                    $needs_update = true;
                    $r['brand_id'] = 1; // Default to Brand 1 (Wings365)
                }
            }

            // 3. Ensure all existing domains have brand_id
            foreach ($data['domains'] as &$d) {
                if (!isset($d['brand_id'])) {
                    $needs_update = true;
                    $d['brand_id'] = 1; // Default to Brand 1 (Wings365)
                }
            }

            return $data;
        };

        if ($needs_update || !isset($this->data['settings']['brands'])) {
            $this->update_db($callback);
        }
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
    // REDIRECT METHODS (Brand-Aware)
    // ----------------------------------------------------
    public function getRedirects($brand_id = null) {
        $this->load();
        if ($brand_id === null) {
            return $this->data['redirects'];
        }
        $brand_id = intval($brand_id);
        return array_values(array_filter($this->data['redirects'], function($r) use ($brand_id) {
            return intval($r['brand_id'] ?? 1) === $brand_id;
        }));
    }

    public function getRedirectBySlugAndBrand($slug, $brand_id) {
        $this->load();
        $slug = strtolower(trim($slug));
        $brand_id = intval($brand_id);
        foreach ($this->data['redirects'] as $r) {
            if (strtolower($r['slug']) === $slug && intval($r['brand_id'] ?? 1) === $brand_id) {
                return $r;
            }
        }
        return null;
    }

    // Backwards compatibility helper
    public function getRedirectBySlug($slug) {
        return $this->getRedirectBySlugAndBrand($slug, 1);
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

    public function addRedirect($slug, $target_url, $status = 1, $brand_id = 1) {
        $id = time() . rand(100, 999);
        $this->update_db(function($data) use ($id, $slug, $target_url, $status, $brand_id) {
            $data['redirects'][] = [
                'id' => intval($id),
                'brand_id' => intval($brand_id),
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
    // CLICK LOG METHODS (Brand-Aware)
    // ----------------------------------------------------
    public function getLogs($brand_id = null) {
        $this->load();
        if ($brand_id === null) {
            return $this->data['click_logs'];
        }
        $brand_id = intval($brand_id);
        
        // Find redirects belonging to this brand
        $brand_redirect_ids = [];
        foreach ($this->data['redirects'] as $r) {
            if (intval($r['brand_id'] ?? 1) === $brand_id) {
                $brand_redirect_ids[] = intval($r['id']);
            }
        }
        
        return array_values(array_filter($this->data['click_logs'], function($log) use ($brand_redirect_ids) {
            return in_array(intval($log['redirect_id']), $brand_redirect_ids);
        }));
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

    public function clearLogs($brand_id = null) {
        return $this->update_db(function($data) use ($brand_id) {
            if ($brand_id === null) {
                $data['click_logs'] = [];
                foreach ($data['redirects'] as &$r) {
                    $r['clicks'] = 0;
                }
            } else {
                $brand_id = intval($brand_id);
                // Reset redirect click counters for this brand
                $brand_redirect_ids = [];
                foreach ($data['redirects'] as &$r) {
                    if (intval($r['brand_id'] ?? 1) === $brand_id) {
                        $r['clicks'] = 0;
                        $brand_redirect_ids[] = intval($r['id']);
                    }
                }
                // Delete logs belonging to this brand
                foreach ($data['click_logs'] as $log_key => $log) {
                    if (in_array(intval($log['redirect_id']), $brand_redirect_ids)) {
                        unset($data['click_logs'][$log_key]);
                    }
                }
                $data['click_logs'] = array_values($data['click_logs']);
            }
            return $data;
        });
    }

    public function getLogsCount24h($brand_id = null) {
        $logs = $this->getLogs($brand_id);
        $count = 0;
        $now = time();
        foreach ($logs as $log) {
            $logged_time = strtotime($log['clicked_at']);
            if (($now - $logged_time) <= 86400) {
                $count++;
            }
        }
        return $count;
    }

    // ----------------------------------------------------
    // DOMAIN ROTATION METHODS (Brand-Aware)
    // ----------------------------------------------------
    public function getDomains($brand_id = null) {
        $this->load();
        if ($brand_id === null) {
            return $this->data['domains'];
        }
        $brand_id = intval($brand_id);
        return array_values(array_filter($this->data['domains'], function($d) use ($brand_id) {
            return intval($d['brand_id'] ?? 1) === $brand_id;
        }));
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

    public function addDomain($domain, $brand_id = 1) {
        $domain = strtolower(trim(preg_replace('/^https?:\/\//i', '', $domain)));
        $domain = rtrim($domain, '/');
        
        if (empty($domain)) return false;
        
        $brand_id = intval($brand_id);
        
        // Check if domain already exists (globally to avoid collisions)
        foreach ($this->data['domains'] as $d) {
            if ($d['domain'] === $domain) {
                return false;
            }
        }

        $id = time() . rand(100, 999);
        
        return $this->update_db(function($data) use ($id, $domain, $brand_id) {
            // Check if there is already an active domain for this brand
            $has_active = false;
            foreach ($data['domains'] as $d) {
                if ($d['status'] === 'active' && intval($d['brand_id'] ?? 1) === $brand_id) {
                    $has_active = true;
                    break;
                }
            }
            
            $status = $has_active ? 'clean' : 'active';
            
            $data['domains'][] = [
                'id' => intval($id),
                'brand_id' => $brand_id,
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
            $brand_id = 1;
            foreach ($data['domains'] as $key => $d) {
                if (intval($d['id']) === intval($id)) {
                    $brand_id = intval($d['brand_id'] ?? 1);
                    if ($d['status'] === 'active') {
                        $deleted_active = true;
                    }
                    unset($data['domains'][$key]);
                    $data['domains'] = array_values($data['domains']);
                    break;
                }
            }
            
            // If the active domain was deleted, activate the next clean one for this brand
            if ($deleted_active && !empty($data['domains'])) {
                foreach ($data['domains'] as &$d) {
                    if ($d['status'] === 'clean' && intval($d['brand_id'] ?? 1) === $brand_id) {
                        $d['status'] = 'active';
                        break;
                    }
                }
            }
            return $data;
        });
    }

    public function getActiveDomain($brand_id = 1) {
        $this->load();
        $brand_id = intval($brand_id);
        
        // Find active domain for this brand
        foreach ($this->data['domains'] as $d) {
            if ($d['status'] === 'active' && intval($d['brand_id'] ?? 1) === $brand_id) {
                return $d['domain'];
            }
        }
        
        // Fallback: search for first clean domain for this brand and make it active
        $activated_domain = null;
        $this->update_db(function($data) use ($brand_id, &$activated_domain) {
            foreach ($data['domains'] as &$d) {
                if ($d['status'] === 'clean' && intval($d['brand_id'] ?? 1) === $brand_id) {
                    $d['status'] = 'active';
                    $activated_domain = $d['domain'];
                    break;
                }
            }
            return $data;
        });
        
        if ($activated_domain) return $activated_domain;
        
        // Fallback to request host
        return $_SERVER['HTTP_HOST'] ?? 'localhost:8000';
    }

    // Matches domain hostname to find which brand it belongs to (defaults to Brand 1 if not matched)
    public function getBrandIdByHost($host) {
        $this->load();
        $host = strtolower(trim($host));
        foreach ($this->data['domains'] as $d) {
            if ($d['domain'] === $host) {
                return intval($d['brand_id'] ?? 1);
            }
        }
        return 1; // Default fallback to Brand 1
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

    public function rotateDomain($brand_id = 1) {
        $brand_id = intval($brand_id);
        return $this->update_db(function($data) use ($brand_id) {
            $active_key = null;
            foreach ($data['domains'] as $key => $d) {
                if ($d['status'] === 'active' && intval($d['brand_id'] ?? 1) === $brand_id) {
                    $active_key = $key;
                    break;
                }
            }
            
            // Find a backup domain that is clean for this brand
            $next_clean_key = null;
            foreach ($data['domains'] as $key => $d) {
                if ($d['status'] === 'clean' && intval($d['brand_id'] ?? 1) === $brand_id) {
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
                if ($active_key !== null) {
                    $data['domains'][$active_key]['blocked_reason'] = 'Flagged as blocked, but no clean backup domains are available!';
                    $data['domains'][$active_key]['last_checked'] = date('Y-m-d H:i:s');
                }
            }
            return $data;
        });
    }

    // ----------------------------------------------------
    // SETTINGS METHODS (Global & Brand-Aware)
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

    public function getBrandSetting($brand_id, $key) {
        $this->load();
        $brand_id = strval($brand_id);
        return $this->data['settings']['brands'][$brand_id][$key] ?? '';
    }

    public function updateBrandSetting($brand_id, $key, $value) {
        $brand_id = strval($brand_id);
        return $this->update_db(function($data) use ($brand_id, $key, $value) {
            $data['settings']['brands'][$brand_id][$key] = $value;
            return $data;
        });
    }
}

$db = new JsonDatabase();
?>
