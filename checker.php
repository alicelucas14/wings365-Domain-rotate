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
            'timeout' => 2 // Max 2 seconds timeout
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
        curl_setopt($ch, CURLOPT_TIMEOUT, 2);
        $result = curl_exec($ch);
        curl_close($ch);
    }
    
    return $result ? json_decode($result, true) : null;
}

// Helper function to query a specific DNS server using raw UDP sockets in PHP
function queryCustomDNS($domain, $dnsServer) {
    $port = 53;
    $timeout = 1; // 1 second timeout
    
    // 1. Transaction ID (random 16-bit number) and Flags (0x0100 = Standard query, recursion desired)
    $transactionId = rand(10000, 65535);
    $header = pack('n6', $transactionId, 0x0100, 1, 0, 0, 0);
    
    // 2. Format Domain Name (e.g. "google.com" -> "\x06google\x03com\x00")
    $qname = '';
    $parts = explode('.', $domain);
    foreach ($parts as $part) {
        $qname .= chr(strlen($part)) . $part;
    }
    $qname .= "\x00";
    
    // Type A (1), Class IN (1)
    $question = $qname . pack('n2', 1, 1);
    $packet = $header . $question;
    
    // 3. Send over UDP socket
    $socket = @fsockopen("udp://$dnsServer", $port, $errno, $errstr, $timeout);
    if (!$socket) {
        return ['error' => "Socket error: $errstr ($errno)"];
    }
    
    stream_set_timeout($socket, $timeout);
    fwrite($socket, $packet);
    
    $response = fread($socket, 512);
    $info = stream_get_meta_data($socket);
    fclose($socket);
    
    if ($info['timed_out']) {
        return ['error' => 'Timeout'];
    }
    
    if (strlen($response) < 12) {
        return ['error' => 'Invalid DNS response size'];
    }
    
    // 4. Parse Header
    $headerData = unpack('n6', substr($response, 0, 12));
    $resTransactionId = $headerData[1];
    $flags = $headerData[2];
    $qdCount = $headerData[3];
    $anCount = $headerData[4];
    
    if ($resTransactionId !== $transactionId) {
        return ['error' => 'Transaction ID mismatch'];
    }
    
    // Check RCODE (last 4 bits of flags: 0 = No error, 3 = Name Error / NXDOMAIN)
    $rcode = $flags & 0x000F;
    if ($rcode !== 0) {
        return ['error' => 'RCODE error code ' . $rcode, 'rcode' => $rcode];
    }
    
    if ($anCount === 0) {
        return ['ips' => []];
    }
    
    // 5. Skip Question section
    $offset = 12;
    while ($offset < strlen($response)) {
        $len = ord($response[$offset]);
        if ($len === 0) {
            $offset++;
            break;
        }
        if (($len & 0xC0) === 0xC0) {
            $offset += 2;
            break;
        }
        $offset += $len + 1;
    }
    $offset += 4; // Skip QTYPE and QCLASS
    
    // 6. Parse Answers
    $ips = [];
    for ($i = 0; $i < $anCount; $i++) {
        if ($offset >= strlen($response)) {
            break;
        }
        
        $firstByte = ord($response[$offset]);
        if (($firstByte & 0xC0) === 0xC0) {
            $offset += 2;
        } else {
            while ($offset < strlen($response)) {
                $len = ord($response[$offset]);
                if ($len === 0) {
                    $offset++;
                    break;
                }
                $offset += $len + 1;
            }
        }
        
        if ($offset + 10 > strlen($response)) {
            break;
        }
        
        $typeData = unpack('ntype/nclass/Nttl/nrdlength', substr($response, $offset, 10));
        $type = $typeData['type'] ?? 0;
        $rdlength = $typeData['rdlength'] ?? 0;
        $offset += 10;
        
        if ($offset + $rdlength > strlen($response)) {
            break;
        }
        
        $rdata = substr($response, $offset, $rdlength);
        $offset += $rdlength;
        
        if ($type === 1 && $rdlength === 4) { // Type A record
            $ip = ord($rdata[0]) . '.' . ord($rdata[1]) . '.' . ord($rdata[2]) . '.' . ord($rdata[3]);
            $ips[] = $ip;
        }
    }
    
    return ['ips' => $ips];
}

// Function to check if a domain is blocked by Indonesian ISPs (Telkomsel, etc.)
function checkIndonesianIspBlock($domain, $ignoreNxdomain = false) {
    // 1. Check clean resolution using Google DNS to verify if domain actually exists
    $googleRes = queryCustomDNS($domain, '8.8.8.8');
    if (isset($googleRes['error']) || empty($googleRes['ips'])) {
        // Domain doesn't resolve globally (NXDOMAIN/Offline), so it is not active or hasn't propagated.
        // We do not treat this as an ISP block event, but DNS BL or Google Safe Browsing can handle it.
        return ['blocked' => false, 'reason' => ''];
    }
    
    $cleanIps = $googleRes['ips'];
    
    // Known Indonesian DNS servers that enforce TrustPositif/Internet Positif blocking
    $indonesianDnsServers = [
        'APJII DNS Bersama 1' => '103.88.88.88',
        'APJII DNS Bersama 2' => '103.88.88.99',
        'Telkom Speedy/IndiHome DNS' => '203.130.196.155',
        'Biznet DNS' => '202.169.33.33',
        'XL/Axis DNS' => '202.152.240.50'
    ];
    
    // Known TrustPositif / Internet Positif redirect/hijack IP patterns
    // We check if resolved IP matches standard block/loopback/government block ranges
    $blockedIpPrefixes = [
        '36.86.63.',   // Telkom internetpositif.id landing range
        '118.98.97.',  // Older Telkom block page IP range
        '203.119.13.', // Kominfo / TrustPositif block page IP range
        '203.119.14.', // Kominfo / TrustPositif block page IP backup range
        '127.0.0.',    // Localhost redirect blocks
        '0.0.0.0'
    ];
    
    foreach ($indonesianDnsServers as $dnsName => $dnsIp) {
        // --- SANITY CHECK: Ensure we can query this DNS server from our location ---
        $testRes = queryCustomDNS('google.com', $dnsIp);
        if (isset($testRes['error']) || empty($testRes['ips'])) {
            // If we cannot resolve google.com on this server, it means the DNS server is blocking
            // external queries, or is down/unreachable from our server. We must skip it.
            continue;
        }

        $res = queryCustomDNS($domain, $dnsIp);
        
        // If we hit a timeout or transport error on a specific Indonesian DNS, we try the next one
        if (isset($res['error'])) {
            continue;
        }
        
        // If it returns Name Error (NXDOMAIN / RCODE 3) from Indonesian DNS while resolving fine on Google DNS,
        // it means the domain is blocked/dropped by the Indonesian DNS server.
        if (isset($res['rcode']) && $res['rcode'] === 3) {
            if ($ignoreNxdomain) {
                continue;
            }
            return [
                'blocked' => true,
                'reason' => "Indonesian ISP DNS ({$dnsName}) blocked the domain (returned NXDOMAIN)"
            ];
        }
        
        $resolvedIps = $res['ips'] ?? [];
        if (empty($resolvedIps)) {
            if ($ignoreNxdomain) {
                continue;
            }
            return [
                'blocked' => true,
                'reason' => "Indonesian ISP DNS ({$dnsName}) failed to resolve domain"
            ];
        }
        
        foreach ($resolvedIps as $ip) {
            // Check if resolved IP is in the blocked patterns
            foreach ($blockedIpPrefixes as $prefix) {
                if (strpos($ip, $prefix) === 0) {
                    return [
                        'blocked' => true,
                        'reason' => "Redirected to Indonesian ISP block page IP ({$ip}) via {$dnsName}"
                    ];
                }
            }
            
            // Check if the resolved IP is completely different from the real IP resolved by Google DNS
            // (Standard DNS hijacking check)
            if (!in_array($ip, $cleanIps)) {
                return [
                    'blocked' => true,
                    'reason' => "Spoofed DNS response detected (resolves to {$ip} instead of real server IP) via {$dnsName}"
                ];
            }
        }
    }
    
    return ['blocked' => false, 'reason' => ''];
}

// Main Blacklist Check function
function checkDomainBlacklist($domain, $safeBrowsingKey = '', $createdAt = '') {
    // Calculate if we should ignore NXDOMAIN/empty resolution (e.g. if the domain is under 24 hours old)
    $ignoreNxdomain = false;
    if (!empty($createdAt) && $createdAt !== 'Never') {
        $created_time = strtotime($createdAt);
        if ($created_time !== false && (time() - $created_time) < 86400) {
            $ignoreNxdomain = true;
        }
    }

    // 1. Check if blocked by Indonesian ISPs (Telkomsel/Internet Positif)
    $ispCheck = checkIndonesianIspBlock($domain, $ignoreNxdomain);
    if ($ispCheck['blocked']) {
        return [
            'blocked' => true,
            'reason' => 'Flagged by Indonesian ISP: ' . $ispCheck['reason']
        ];
    }

    // 2. DNS BL Checks (SURBL & Spamhaus) - Disabled as requested
    /*
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
    */
    
    // 3. Google Safe Browsing API Check (Optional)
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
    $interval_hours = floatval($db->getSetting('check_interval_hours'));
    if ($interval_hours <= 0) $interval_hours = 6;
    $interval_seconds = intval($interval_hours * 3600);
    $apiKey = $db->getSetting('safe_browsing_key');
    
    $rotated_any = false;
    
    // Check all 4 brands
    for ($brand_id = 1; $brand_id <= 4; $brand_id++) {
        // Find active domain for this brand
        $domains = $db->getDomains($brand_id);
        $active_domain = null;
        foreach ($domains as $d) {
            if ($d['status'] === 'active') {
                $active_domain = $d;
                break;
            }
        }
        
        if (!$active_domain) {
            continue; // No active domain for this brand
        }
        
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
            // 1. Verify and rotate landing domain
            $result = checkDomainBlacklist($active_domain['domain'], $apiKey, $active_domain['created_at'] ?? '');
            
            if ($result['blocked']) {
                // Active domain for this brand is blocked! Rotate to the next domain for this brand
                $db->rotateDomain($brand_id, $result['reason']);
                $rotated_any = true;
            } else {
                // Active domain is clean, update last_checked timestamp
                $db->updateDomainStatus($active_domain['id'], 'active', '');
            }
            
            // 2. Verify and rotate active redirect target destinations
            $redirects = $db->getRedirects($brand_id);
            foreach ($redirects as $r) {
                if (intval($r['status']) !== 1) {
                    continue; // Skip inactive redirects
                }
                
                $target_url = $r['target_url'];
                $target_host = parse_url($target_url, PHP_URL_HOST);
                if (empty($target_host)) {
                    continue;
                }
                
                // Query Indonesian ISP check for target host. We ignore NXDOMAIN for target hosts.
                $ispCheck = checkIndonesianIspBlock($target_host, true);
                if ($ispCheck['blocked']) {
                    // Target destination is blocked in Indonesia! Rotate to the next backup URL.
                    $db->rotateRedirectTarget($r['id'], $ispCheck['reason']);
                    $rotated_any = true;
                }
            }
        }
    }
    
    return $rotated_any;
}
?>
