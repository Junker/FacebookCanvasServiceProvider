<?php
namespace Junker\Silex\Security\User;

interface FacebookCanvasUserProviderInterface
{
    public function loadUserByFacebookUid($fbUid);
}