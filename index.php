<?php

function generate_random_hexadecimal_code() {
    return bin2hex(openssl_random_pseudo_bytes(32));
}

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

function create_storage_object($response) {
    $code = generate_random_hexadecimal_code();
    save_storage_object($code, $response);
    return $code;
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
    if(!validate_storage_id($id)) {
        return null;
    }
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
    return $entries;
}

function validate_storage_id($code) {
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

function request_method_is_post() {
    return $_SERVER['REQUEST_METHOD'] == 'POST';
}

function config() {
    $inifile = parse_ini_file('config.ini', true);

    foreach($inifile as $key => $value) {
        $inifile[$key] = (object) $value;
    }
    
    return (object) $inifile;
}

function main() {
    $config = config();
    if(request_method_is_post()) {

        if($_POST['client_id'] != $config->client->client_id and $_POST['client_secret'] != $config->client->client_secret) {
            throw_client_error("Invalid 'client_id' or 'client_secret'");
        }
        
        clear_expired_objects();
        
        if(($response = pop_storage_object($_POST['code'])) != null) {
            write_json_response($response);
        } else {
            throw_client_error("Invalid code");
        }
    } else {
        if($_GET['client_id'] != $config->client->client_id or preg_match($config->client->redirect_uri, $_GET['redirect_uri'])) {
            throw_client_error("Invalid 'client_id' or 'redirect_uri'");
        }
        
        $ldap_user = ldap_login(
            $config->server->hostname,
            $config->server->dn,
            $config->server->sub,
            $_SERVER['PHP_AUTH_USER'],
            $_SERVER['PHP_AUTH_PW']
        );
        
        if(!$ldap_user) {
            require_http_authentication();
        }
        
        $response = oidc_generate_token_response(
            $token,
            array(
                "sub" => $ldap_user[0][$config->server->sub][0],
                "name" => $ldap_user[0][$config->server->name][0],
                "email" => $ldap_user[0][$config->server->email][0]
            )
        );

        $code = create_storage_object($response);

        redirect_to(add_url_query_string($_GET['redirect_uri'], array('state' => $_GET['state'], 'code' => $code)));
    }
}

main();