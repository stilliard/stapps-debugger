<?php

use Slim\Http\Request;
use Slim\Http\Response;

// Routes

$app->get('/', function (Request $request, Response $response) {
    return $this->view->render($response, 'index.twig');
});

$app->get('/spf', function (Request $request, Response $response) {
    return $this->view->render($response, 'spf.twig');
});

$app->post('/spf', function (Request $request, Response $response) {
    // $this->logger->info("SPF check run");
    return $this->view->render($response, 'spf.twig', [
        'params' => $request->getParsedBody(),
    ]);
});
