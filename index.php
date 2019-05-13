<?php


/**
 * generates a 32 bytes random hexadecimal for code workflow
 **/
function generate_random_hexadecimal_code() {
    return bin2hex(openssl_random_pseudo_bytes(32));
}

/**
 * variant of base64 for jwt encoding
 **/
function jwt_base64_encode($data) {
    return str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode($data));
}

function jwt_json_encode($data) {
    return jwt_base64_encode(json_encode($data));
}

function jwt_encode($header, $payload) {
    return jwt_base64_encode($header) . '.' . jwt_json_encode($payload) . '.';
}

function jwt_unsigned_encode($payload) {
    $header = array('typ' => 'JWT', 'alg' => 'none');
    return jwt_encode($header, $payload);
}

function oidc_generate_token_response($access_token, $id_token) {
    return json_encode(array(
        'access_token' => $access_token,
        'id_token' => jwt_unsigned_encode($id_token)
    ));
}


function config() {
    $inifile = parse_ini_file('config.ini', true);
    
    return array(
        'ldap' => array(
            'hostname' => $inifile['server']['hostname'],
            'userdn' => $inifile['server']['dn'],
            'userid' => $inifile['server']['sub'],
            'name' => $inifile['server']['name'],
            'email' => $inifile['ser ver']['email']
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
    
    @rmdir("tokens");
    
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
        
        $json = oidc_generate_token_response(
            $token,
            array(
                "sub" => $entries[0]['uid'][0],
                "name" => $entries[0]['cn'][0],
                "email" => $entries[0]['mail'][0]
            )
        );
    
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