<?php
namespace SilexOpauth\Security;
/**
 * Loads users using opauth result
 *
 * @author Rafal Lindemann
 */
interface FacebookCanvasUserProviderInterface
{
    public function loadUserByFacebookUid($fbUid);
}