<?php
return [
    'settings' => [
        'displayErrorDetails' => false, // true only for local debugging
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header

        // View settings
        'view' => [
            'path' => __DIR__ . '/../views/',
            'cache' => __DIR__ . '/../tmp/cache/',
        ],

        // Monolog settings
        'logger' => [
            'name' => 'stapps-debugger',
            'path' => getenv('docker') ? 'php://stdout' : __DIR__ . '/../logs/app.log',
            'level' => \Monolog\Logger::DEBUG,
        ],
    ],
];
