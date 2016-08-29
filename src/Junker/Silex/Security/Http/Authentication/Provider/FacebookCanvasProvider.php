<?php

namespace Junker\Silex\Security\Http\Authentication\Provider;

use Junker\Silex\Security\Http\Token\FacebookCanvasToken;
use Facebook\FacebookSession;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class FacebookCanvasProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    protected $userProvider;

    protected $providerKey;

    /**
     * Constructor.
     *
     * @param FacebookCanvasUserProviderInterface $userProvider An FacebookCanvasUserProviderInterface instance
     * @param UserCheckerInterface  $userChecker  An UserCheckerInterface instance
     * @param string                $providerKey  The provider key
     * @param string                $appSecret  Facebook App secret key     
     */
    public function __construct(FacebookCanvasUserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey, $appSecret)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->providerKey = $providerKey;
        $this->appSecret = $appSecret;
    }

    /**
     * Attempts to authenticate a TokenInterface object.
     *
     * @param TokenInterface $token The TokenInterface instance to authenticate
     *
     * @return TokenInterface An authenticated TokenInterface instance, never null
     *
     * @throws AuthenticationException if the authentication fails
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return;
        }

        if (!$token->signedRequest) {
            throw new AuthenticationException('FacebookCanvas auth failed');
        }

        $fb_session = null;

        try {
            $fbSignedRequest = new \Facebook\Entities\SignedRequest($token->signedRequest, '', $this->appSecret);
            $fb_session = FacebookSession::newSessionFromSignedRequest($fbSignedRequest);
        } catch (FacebookSDKException $ex) {
            throw AuthenticationException('FacebookCanvas auth failed: ' . $ex->message);
        }

        if ($fb_session) {
            $fb_uid = $fb_session->getSessionInfo()->asArray()['user_id'];
        } else {
            throw new AuthenticationException('FacebookCanvas auth failed');
        }

        $user = $this->userProvider->loadUserByFacebookUid($fb_uid);

        if (!$user instanceof UserInterface) {
            throw new AuthenticationServiceException('loadUserByFacebookUID() must return a UserInterface.');
        }

        $this->userChecker->checkPostAuth($user);

        $token = new FacebookCanvasToken($token->signedRequest,
            $token->providerKey,
            $this->getRoles($user)
        );

        $token->setUser($user);
        $token->setAuthenticated(true);

        return $token;
    }

    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     *
     * @return bool    true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof FacebookCanvasToken;
    }

    /**
     * @param UserInterface  $user  The user
     *
     * @return array The user roles
     */
    private function getRoles(UserInterface $user)
    {
        $roles = $user->getRoles();

        $roles[] = 'ROLE_FACEBOOK_CANVAS';

        return $roles;
    }
}
