<?php
// Blacklist Checking and Domain Rotation Logic
require_once __DIR__ . '/database.php';

// Helper to make POST request compatible with standard PHP installations
function checker_post_json($url, $data) {
    $json_content = json_encode($data);
    $options = [
        'http' => [
            'header'  => "Content-Type: application/json\r\n",
            'method'  => 'POST',
            'content' => $json_content,
            'timeout' => 5 // Max 5 seconds timeout
        ]
    ];
    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);
    
    // Fallback to Curl if file_get_contents is restricted by server configuration
    if ($result === false && function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json_content);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $result = curl_exec($ch);
        curl_close($ch);
    }
    
    return $result ? json_decode($result, true) : null;
}

// Main Blacklist Check function
function checkDomainBlacklist($domain, $safeBrowsingKey = '') {
    // 1. DNS BL Checks (SURBL & Spamhaus) - Keyless and free
    // Normalize domain for DNS lookup (remove www. if present)
    $lookup_domain = preg_replace('/^www\./i', '', $domain);
    
    // SURBL (Multi.surbl.org)
    $surbl_flagged = @checkdnsrr($lookup_domain . '.multi.surbl.org', 'A');
    
    // Spamhaus DBL (dbl.spamhaus.org)
    $spamhaus_flagged = @checkdnsrr($lookup_domain . '.dbl.spamhaus.org', 'A');
    
    if ($surbl_flagged || $spamhaus_flagged) {
        $reasons = [];
        if ($surbl_flagged) $reasons[] = 'SURBL Blocklist';
        if ($spamhaus_flagged) $reasons[] = 'Spamhaus DBL';
        return [
            'blocked' => true,
            'reason' => 'Flagged by DNS blocklist (' . implode(', ', $reasons) . ')'
        ];
    }
    
    // 2. Google Safe Browsing API Check (Optional)
    if (!empty($safeBrowsingKey)) {
        $api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" . $safeBrowsingKey;
        $request_data = [
            'client' => [
                'clientId' => 'linkupdater',
                'clientVersion' => '1.0.0'
            ],
            'threatInfo' => [
                'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => [
                    ['url' => 'http://' . $domain],
                    ['url' => 'https://' . $domain]
                ]
            ]
        ];
        
        $response = checker_post_json($api_url, $request_data);
        
        if ($response && !empty($response['matches'])) {
            $threatType = $response['matches'][0]['threatType'] ?? 'Malware/Phishing';
            return [
                'blocked' => true,
                'reason' => 'Flagged by Google Safe Browsing (' . htmlspecialchars($threatType) . ')'
            ];
        }
    }
    
    return [
        'blocked' => false,
        'reason' => ''
    ];
}

// Auto checker executor (checks at most once every interval unless forced)
function runAutoCheck($db, $force = false) {
    // Fetch active domain from DB
    $domains = $db->getDomains();
    $active_domain = null;
    foreach ($domains as $d) {
        if ($d['status'] === 'active') {
            $active_domain = $d;
            break;
        }
    }
    
    if (!$active_domain) return false; // No active domain to check
    
    $interval_hours = intval($db->getSetting('check_interval_hours'));
    if ($interval_hours <= 0) $interval_hours = 6;
    $interval_seconds = $interval_hours * 3600;
    
    $needs_check = false;
    if ($force || $active_domain['last_checked'] === 'Never') {
        $needs_check = true;
    } else {
        $last_time = strtotime($active_domain['last_checked']);
        if ($last_time === false || (time() - $last_time) >= $interval_seconds) {
            $needs_check = true;
        }
    }
    
    if ($needs_check) {
        $apiKey = $db->getSetting('safe_browsing_key');
        $result = checkDomainBlacklist($active_domain['domain'], $apiKey);
        
        if ($result['blocked']) {
            // Active domain is blocked! Rotate to the next domain
            $db->rotateDomain();
            return true; // Rotated
        } else {
            // Active domain is clean, update last_checked timestamp
            $db->updateDomainStatus($active_domain['id'], 'active', '');
        }
    }
    
    return false; // Not rotated
}
?>
