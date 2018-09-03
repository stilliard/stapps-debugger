<?php
return [
    'settings' => [
        'displayErrorDetails' => true, // set to false in production
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header

        // View settings
        'view' => [
            'path' => __DIR__ . '/../views/',
            'cache' => __DIR__ . '/../tmp/cache/',
        ],

        // Monolog settings
        'logger' => [
            'name' => 'stapps-debugger',
            'path' => isset($_ENV['docker']) ? 'php://stdout' : __DIR__ . '/../logs/app.log',
            'level' => \Monolog\Logger::DEBUG,
        ],
    ],
];
