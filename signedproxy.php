<?php

// what this script does:
// 1. validate a) timestamp and b) HMAC signature
// 2. check against list of known spammers
// 3. pass along to GA

//  options
$debug=0; // verbose output & call to debug GA collector

$ga_api_key = "yourapikey"; // this is your GA "API" key, used by GA filter, keep private.
$hmac_private_key = "yoursecretkey"; // signing key, also keep private
$custom_dim_index = 1;

$junk=0;
$junk_rule='';

// #1a verify time window (original request time shouldn't be off by > 5 minutes)
if (abs($_SERVER['REQUEST_TIME'] - $_REQUEST['request_time']) > 300){
    if ($debug){
        print "sorry, time verification failed\n";
    }
    $junk=1;
    $junk_rule="timewindow ";
}

// #1b validate HMAC
// this requires match of UA, HOST as well as working HTTP_REFERRER
$request_to_validate = $_SERVER['HTTP_USER_AGENT'] . ":" . $_SERVER['HTTP_HOST'] . ":" . $_REQUEST['uri'] . ":" . $_REQUEST['request_time'];
$hmac_sig = base64_encode(hash_hmac('sha256', $request_to_validate, $hmac_private_key, true));

if ($hmac_sig != $_REQUEST['hmac_sig']){
    print "sorry, hmac signature failed\n";
    if ($debug){
        print "$hmac_sig != {$_REQUEST['hmac_sig']}\n";
        print "{$_SERVER['HTTP_USER_AGENT']} {$_SERVER['HTTP_HOST']} {$_REQUEST['uri']} {$_REQUEST['request_time']}";
    }
    $junk=1;
    $junk_rule.="hmac ";
}

// #2 check for spam
// note this checks individual hits for spam URLs, not tied to a session
$spam_file = "spamurls.txt";
$remote_spam_file = "https://d12q3rc0hnqb3v.cloudfront.net/ga-filter/$spam_file";
$spam_urls = '';

if (file_exists($spam_file) && (filemtime($spam_file) > (time() - 3600*12))){
    // TTL of 12 hours
    $spam_urls = file($spam_file);
}else{
    $spam_urls = file($remote_spam_file);
    file_put_contents($spam_file, implode('',$spam_urls), LOCK_EX);
}

foreach ($_REQUEST as $ga_var){
    // check every submitted field against blacklist
    foreach ($spam_urls as $spam_url){
        if (stripos($ga_var, $spam_url)){
            $junk=1;
            $junk_rule.="spam ";
            // break out of both foreach loop
            break 2;
        }
    }
}


// #3 prepare request & send to GA
$ga_request = $_REQUEST;

// take out the parts of the request we added for proxy and don't want to pass along to GA
unset($ga_request['request_time'], $ga_request['hmac_sig'], $ga_request['uri']);

// add back in the original user IP
// note that manual use of uip means the IP gets automatically anonymized, thus breaking IP-specific filters
$ga_request['uip']  = get_ip_address();
$ga_request["cd{$custom_dim_index}"] = $ga_api_key;

if ($junk > 0){
   // could also send to a different property here rather than just existing.
   exit;
}

$gamp_base_url = "https://www.google-analytics.com/collect?";
if ($debug){
    $gamp_base_url = "https://www.google-analytics.com/debug/collect?";
}

$gamp_url = $gamp_base_url . http_build_query($ga_request);

header("Content-type: image/gif");
$curl = curl_init($gamp_url);
// pass along the same UA and referrer as original request (not cURL from server IP)
curl_setopt($curl, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($curl, CURLOPT_REFERER, $_SERVER['HTTP_REFERER']);
$gamp_response = curl_exec($curl);
curl_close($curl);

if ($debug){
    print $gamp_response;
}


function get_ip_address(){
    //http://stackoverflow.com/questions/1634782/what-is-the-most-accurate-way-to-retrieve-a-users-correct-ip-address-in-php
    foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key){
        if (array_key_exists($key, $_SERVER) === true){
            foreach (explode(',', $_SERVER[$key]) as $ip){
                $ip = trim($ip); // just to be safe
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false){
                    return $ip;
                }
            }
        }
    }
}
