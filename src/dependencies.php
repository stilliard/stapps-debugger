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

// view renderer using Twig 3 directly
$container['view'] = function ($container) {
    $settings = $container->get('settings')['view'];
    $loader = new \Twig\Loader\FilesystemLoader($settings['path']);
    $twig = new \Twig\Environment($loader, [
        'cache' => $settings['cache'],
        'auto_reload' => true,
        'debug' => true,
    ]);
    $twig->addExtension(new \Twig\Extension\DebugExtension());
    $twig->addExtension(new Stapps\TwigExtensions\CsrfExtension($container->get('csrf')));

    return new class($twig) {
        public function __construct(private \Twig\Environment $twig) {}
        public function render($response, string $template, array $data = []) {
            $body = $this->twig->render($template, $data);
            $response->getBody()->write($body);
            return $response;
        }
    };
};

// monolog
$container['logger'] = function ($c) {
    $settings = $c->get('settings')['logger'];
    $logger = new Monolog\Logger($settings['name']);
    $logger->pushProcessor(new Monolog\Processor\UidProcessor());
    $logger->pushHandler(new Monolog\Handler\StreamHandler($settings['path'], $settings['level']));
    return $logger;
};
