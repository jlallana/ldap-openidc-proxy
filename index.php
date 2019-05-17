<?php

function generate_secret_code() {
    return bin2hex(openssl_random_pseudo_bytes(32));
}

function jwt_base64_encode($data) {
    return str_replace(array('+', '/', '='), array('-', '_', ''), @base64_encode($data));
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
    return array(
        'access_token' => $access_token,
        'id_token' => jwt_unsigned_encode($id_token)
    );
}

function get_storage_dir() {
    return sys_get_temp_dir() . '/' . md5(__FILE__);
}

function save_storage_object($code, $response) {
    @mkdir(get_storage_dir());
    file_put_contents(get_storage_dir()  .  "/$code", json_encode($response));
}

function get_storage_object_filename($id) {
    return get_storage_dir() . "/$id";
}

function load_storage_object($id) {
    $filename = get_storage_object_filename($id);
    if(!file_exists($filename)) {
        return null;
    }
    return json_decode(file_get_contents($filename));
}

function remove_storage_object($id) {
    @unlink(get_storage_object_filename($id));
}

function pop_storage_object($id) {
    $result = load_storage_object($id);
    remove_storage_object($id);
    cleanup_storage();
    return $result;
}

function cleanup_storage() {
    @rmdir(get_storage_dir());
}

function expire_storage_objects($time) {
    foreach(glob(get_storage_dir() . '/*') as $token_file) {
        if((time() - filectime($token_file)) > $time) {
            @unlink($token_file);
        }
    }
}

function clear_expired_objects() {
    expire_storage_objects(10);
}

function throw_client_error($message) {
    http_response_code(400);
    header("Content-Type: text/plain");
    echo $message;
    die;
}

function throw_not_found() {
    http_response_code(404);
    header("Content-Type: text/plain");
    die;
}

function ldap_login($hostname, $dn, $uid,  $username, $password) {
    if(!username_is_valid($username)) {
        return false;
    }
    $ldap = ldap_connect($hostname);
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    $bind = @ldap_bind($ldap, "$uid=$username,$dn", $password);
    if(!$bind) {
        return false;
    }
    $result = ldap_read($ldap, "$uid=$username,$dn", "($uid=$username)");
    $entries = ldap_get_entries($ldap, $result);
    return $entries[0];
}

function ldap_map_attributes($attributes, $mapping) {
    $result = array();
    foreach($mapping as $source => $dest) {
        $result[$dest] = $attributes[$source][0];
    }
    return $result;
}

function validate_secret_code($code) {
    return @hex2bin($code) != null and strlen($code) == 64;
}

function write_json_response($data) {
    header("Context-Type: application/json");
    echo json_encode($data);
}

function require_http_authentication() {
    header('WWW-Authenticate: Basic');
    header('HTTP/1.0 401 Unauthorized');
    header('Content-Type: text/plain');
    echo 'HTTP/1.0 401 Unauthorized';
}

function username_is_valid($username) {
    return ctype_alpha($username);
}

function add_url_query_string($url, $variables) {
    return $url . '?' . http_build_query($variables);
}

function redirect_to($url) {
    header("Location: $url");
}

function request_method() {
    return strtolower($_SERVER['REQUEST_METHOD']);
}

function get_request_base_url() {
    return $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'];
}

function config() {
    $inifile = parse_ini_file('config.ini', true);

    foreach($inifile as $key => $value) {
        $inifile[$key] = (object) $value;
    }
    
    return (object) $inifile;
}

function openid_signin_ok($redirect_uri, $code, $state) {
    redirect_to(add_url_query_string($redirect_uri, array('state' => $state, 'code' => $code)));
}

function process_authentication_page($redirect_uri, $client_id, $response_type, $scope, $state, $auth_user, $auth_pw) {
    $config = config();
    
    if($response_type != 'code') {
        throw_client_error("Invalid 'response_type'");
    }
    
    if($scope != 'openid') {
        throw_client_error("Invalid 'scope'");
    }
    
    
    if($config->client->client_id != $client_id or preg_match($config->client->valid_redirect_uri, $redirect_uri)) {
        throw_client_error("Invalid 'client_id' or 'redirect_uri'");
    }
    
    $ldap_user = ldap_login(
        $config->server->hostname,
        $config->server->dn,
        $config->server->sub,
        $auth_user,
        $auth_pw
    );
    
    if(!$ldap_user) {
        require_http_authentication();
    }

    $secret_code = generate_secret_code();

    $response = oidc_generate_token_response(
        $secret_code,
        ldap_map_attributes($ldap_user, array(
            $config->server->sub => 'sub',
            $config->server->name => 'name',
            $config->server->email => 'email'
        ))
    );

    save_storage_object($secret_code, $response);

    openid_signin_ok($redirect_uri, $secret_code, $state);
}


function process_token_page($client_id, $client_secret, $grant_type, $code) {
    $config = config();

    if(!validate_secret_code($code)) {
        throw_client_error("Invalid code");
    }
    
    if($grant_type != 'authorization_code') {
        throw_client_error("Invalid 'grant_type'");
    }

    if($client_id != $config->client->client_id and $client_secret != $config->client->client_secret) {
        throw_client_error("Invalid 'client_id' or 'client_secret'");
    }

    clear_expired_objects();
    
    if(($response = pop_storage_object($code)) != null) {
        write_json_response($response);
    } else {
        throw_client_error("Invalid code");
    }
}

function process_discovery_page($base_url) {
    write_json_response(array(
        'issuer' => $base_url,
        'authorization_endpoint' => "$base_url/api/oauth/v2/auth",
        'token_endpoint' => "$base_url/api/oauth/v2/token",
        'response_types_supported' => array("code"),
        'id_token_signing_alg_values_supported' => array('none'),
        'scopes_supported' => array('openid'),
        'token_endpoint_auth_methods_supported' => array('client_secret_post'),
        'claims_supported' => array('sub', 'name', 'email'),
        'code_challenge_methods_supported' => array('plain')
    ));
}


function request_path() {
    return isset($_SERVER["REDIRECT_URL"]) ? $_SERVER["REDIRECT_URL"] : '/';
}

function main() {
    if(request_path() == '/api/oauth/v2/token' and request_method() == 'post') {
        process_token_page(
            $_POST['client_id'],
            $_POST['client_secret'],
            $_POST['grant_type'],
            $_POST['code']
        );
    } else if(request_path() == '/api/oauth/v2/auth' and request_method() == 'get') {
        
        process_authentication_page(
            $_GET['redirect_uri'],
            $_GET['client_id'],
            $_GET['response_type'],
            $_GET['scope'],
            $_GET['state'],
            $_SERVER['PHP_AUTH_USER'],
            $_SERVER['PHP_AUTH_PW']
        );
    } else if(request_path() == '/.well-known/openid-configuration' and request_method() == 'get') {
        process_discovery_page(get_request_base_url());
    } else {
        throw_not_found();
    }
}

main();