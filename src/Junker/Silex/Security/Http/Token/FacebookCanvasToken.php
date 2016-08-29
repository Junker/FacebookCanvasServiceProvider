<?php

namespace Junker\Silex\Security\Http\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class FacebookCanvasToken extends AbstractToken
{
    public $fbUid;

    public function __construct($fbUid, $providerKey, array $roles = array())
    {
        parent::__construct($roles);

        $this->fbUid = $fbUid;
        $this->providerKey = $providerKey;

        // If the user has roles, consider it authenticated
        $this->setAuthenticated(count($roles) > 0);
    }

    public function getCredentials()
    {
        return '';
    }

    public function serialize()
    {
        return serialize(array(
            $this->fbUid,
            $this->providerKey,
            parent::serialize(),
        ));
    }
    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list($this->fbUid, $this->providerKey, $parentStr) = unserialize($serialized);
        parent::unserialize($parentStr);
    }
}