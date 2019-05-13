<?php

$config = array(
    'ldap' => array(
        'hostname' => 'ldap.forumsys.com',
        'userdn' => 'dc=example,dc=com',
        'userid' => 'uid',
        'name' => 'cn',
        'email' => 'mail'
    ),
    'clients' => array(
        'nextcloud' => array(
            'redirect_uri' => 'https://nextcloud-jlallana.c9users.io/apps/sociallogin/custom_oidc/test',
            'client_secret' => 'af5037782c2549f5ad9da7c16d95bb7184eaad0c3c864821b6a9047bbb507286'
        )
    )
);