<?php
// DIC configuration

require_once __DIR__ . '/helpers.php';

$container = $app->getContainer();

// csrf
$container['csrf'] = function ($c) {
    $guard = new \Slim\Csrf\Guard();
    $guard->setFailureCallable(function ($request, $response, $next) use ($c) {
        $request = $request->withAttribute("csrf_status", false);
        if (false === $request->getAttribute('csrf_status')) {
            // display suitable error here
            return $c->view->render($response, 'error.twig', ['msg' => 'Page expired / CSRF security failed. Please try again.']);
        } else {
            // successfully passed CSRF check
        }
        return $next($request, $response);
    });
    return $guard;
};

// view renderer
$container['view'] = function ($container) {
    $settings = $container->get('settings')['view'];
    $view = new \Slim\Views\Twig($settings['path'], [
        'cache' => $settings['cache'],
        'auto_reload' => true,
        'debug' => true,
    ]);

    // Instantiate and add Slim specific extension
    $basePath = rtrim(str_ireplace('index.php', '', $container->get('request')->getUri()->getBasePath()), '/');
    $view->addExtension(new Slim\Views\TwigExtension($container->get('router'), $basePath));

    $view->addExtension(new Twig_Extension_Debug());

    $view->addExtension(new Stapps\TwigExtensions\CsrfExtension($container->get('csrf')));

    return $view;
};

// monolog
$container['logger'] = function ($c) {
    $settings = $c->get('settings')['logger'];
    $logger = new Monolog\Logger($settings['name']);
    $logger->pushProcessor(new Monolog\Processor\UidProcessor());
    $logger->pushHandler(new Monolog\Handler\StreamHandler($settings['path'], $settings['level']));
    return $logger;
};
