<?php

namespace Junker\Silex\Security\Http\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class FacebookCanvasToken extends AbstractToken
{
    public $signedRequest;

    public function __construct($signedRequest, $providerKey, array $roles = array())
    {
        parent::__construct($roles);

        $this->signedRequest = $signedRequest;
        $this->providerKey = $providerKey;

        // If the user has roles, consider it authenticated
        $this->setAuthenticated(count($roles) > 0);
    }

    public function getCredentials()
    {
        return '';
    }
}