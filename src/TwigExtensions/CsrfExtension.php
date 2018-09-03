<?php
// CSRF protection helper for twig

namespace Stapps\TwigExtensions;

class CsrfExtension extends \Twig_Extension
{
    public function __construct(\Slim\Csrf\Guard $csrf)
    {
        $this->csrf = $csrf;
    }

    public function getFunctions()
    {
        return [
            new \Twig_Function('csrf', [$this, 'generateCsrfInputs'], [
                'is_safe' => ['html'],
            ]),
        ];
    }

    public function generateCsrfInputs()
    {
        // CSRF token name and value
        $csrfNameKey = $this->csrf->getTokenNameKey();
        $csrfValueKey = $this->csrf->getTokenValueKey();
        $csrfName = $this->csrf->getTokenName();
        $csrfValue = $this->csrf->getTokenValue();

        return '
            <input type="hidden" name="' . $csrfNameKey . '" value="' . $csrfName . '">
            <input type="hidden" name="' . $csrfValueKey . '" value="' . $csrfValue . '">
        ';
    }

    public function getName()
    {
        return 'slim/csrf';
    }
}
