<?php


function config() {
    $inifile = parse_ini_file('config.ini', true);
    
    return array(
        'ldap' => array(
            'hostname' => $inifile['server']['hostname'],
            'userdn' => $inifile['server']['dn'],
            'userid' => $inifile['server']['sub'],
            'name' => $inifile['server']['name'],
            'email' => $inifile['server']['email']
        ),
        'clients' => array(
            $inifile['client']['client_id'] => array(
                'redirect_uri' => $inifile['client']['valid_redirect_uri'],
                'client_secret' => $inifile['client']['client_secret']
            )
        )
    );

}


if($_SERVER['REQUEST_METHOD'] == 'POST') {
    $config = config();

    $client = $config['clients'][$_POST['client_id']];
    
    if(!$client or $client['client_secret'] != $_POST['client_secret'] ) {
        
        http_response_code(400);
        header("Content-Type: text/plain");
        echo "Invalid 'client_id' or 'client_secret'";
        exit;
    
    }
    
    foreach(glob('tokens/*') as $token) {
        if((time() - filectime($token)) > 60) {
            unlink($token);
        }
    
    }
    
    
    $code = $_POST['code'];
    
    if(!@hex2bin($code)) {
        return;
    }
    
    $filename = "tokens/$code.json";
    
    if(!file_exists($filename)) {
        return;
    }
    
    $result = file_get_contents($filename);
    unlink($filename);
    
    header("Context-Type: application/json");
    echo $result;
} else {
    $config = config();

    $client = $config['clients'][$_GET['client_id']];
    
    if(!$client or preg_match($client['redirect_uri'] , $_GET['redirect_uri'])) {
        http_response_code(400);
        header("Content-Type: text/plain");
        echo "Invalid 'client_id' or 'redirect_uri'";
        exit;
    }
    
    function generate_code() {
        return bin2hex(openssl_random_pseudo_bytes(24));
    }
    
    function jwt_binary_encode($data) {
        return str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode($data));
    }
    
    function jwt_encode($payload) {
        $header = jwt_binary_encode(json_encode(array(
            "typ" => "JWT",
            "alg" => "none"
        )));
        
        $payload = jwt_binary_encode(json_encode($payload));
        
        $body = "$header.$payload";
    
        return "$body.";
    }
    
    
    function ldap_login($username, $password) {
        
        $config = config();
    
        $ldap = ldap_connect($config['ldap']['hostname']);
        
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        
        $dn = $config['ldap']['userdn'];
        $uid = $config['ldap']['userid'];
        
        $bind = @ldap_bind($ldap, "$uid=$username,$dn", $password);
    
        if(!$bind) {
            return false;
        }
        
        
        $result = ldap_read($ldap, "$uid=$username,$dn", "($uid=$username)");
        $entries = ldap_get_entries($ldap, $result);
        return $entries;
    }
    
    function login($username, $password) {
        if(!ctype_alpha($username)) {
            return false;
        }
        
        $entries = ldap_login($username, $password);
        
        if(!$entries) {
            return false;
        }
        
        $token = generate_code();
        $json = json_encode(array(
            'access_token' => md5($token),
            'id_token' => jwt_encode(array(
                "sub" => $entries[0]['uid'][0],
                "name" => $entries[0]['cn'][0],
                "email" => $entries[0]['mail'][0]
            ))
        ));
    
        @mkdir('tokens');
        
        file_put_contents("tokens/$token.json", $json);
        
        return $token;
    }
    
    
    if($code = login($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
        $config = config();
    
        header('location: '. $_GET['redirect_uri']. '?state=' . $_GET['state'] . '&code='.  $code);
    } else {
        header('WWW-Authenticate: Basic realm=c9users');
        header('HTTP/1.0 401 Unauthorized');
        header('Content-Type: text/plain');
        echo 'HTTP/1.0 401 Unauthorized';
    }
}