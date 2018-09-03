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
    $params = $request->getParsedBody();

    $domain = domainFromEmail($params['email']);
    list($status, $spf) = spfChecker($domain, $params['ip']);

    return $this->view->render($response, 'spf.twig', compact('params', 'domain', 'spf', 'status'));
});
