<?php

namespace Stapps\TwigExtensions;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class CsrfExtension extends AbstractExtension
{
    public function __construct(private \Slim\Csrf\Guard $csrf)
    {
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('csrf', [$this, 'generateCsrfInputs'], [
                'is_safe' => ['html'],
            ]),
        ];
    }

    public function generateCsrfInputs(): string
    {
        $csrfNameKey = $this->csrf->getTokenNameKey();
        $csrfValueKey = $this->csrf->getTokenValueKey();
        $csrfName = $this->csrf->getTokenName();
        $csrfValue = $this->csrf->getTokenValue();

        return '
            <input type="hidden" name="' . $csrfNameKey . '" value="' . $csrfName . '">
            <input type="hidden" name="' . $csrfValueKey . '" value="' . $csrfValue . '">
        ';
    }
}
