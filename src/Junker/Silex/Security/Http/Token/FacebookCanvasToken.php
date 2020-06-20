<?php

namespace Junker\Silex\Security\Http\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class FacebookCanvasToken extends AbstractToken
{
    public $fbUid;

    public function __construct($fbUid, array $roles = array())
    {
        parent::__construct($roles);

        $this->fbUid = $fbUid;

        // If the user has roles, consider it authenticated
        $this->setAuthenticated(count($roles) > 0);
    }

    public function getCredentials()
    {
        return '';
    }

    public function __serialize(): array
    {
        return [$this->fbUid, parent::__serialize()];
    }

    public function __unserialize(array $data): void
    {
        list($this->fbUid, $parentData) = $data;
        $parentData = \is_array($parentData) ? $parentData : unserialize($parentData);
        parent::__unserialize($parentData);
    }
}
