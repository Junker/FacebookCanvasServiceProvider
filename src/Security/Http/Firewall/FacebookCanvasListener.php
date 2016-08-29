<?php
namespace Junker\Silex\Security\Http\Firewall;

use Silex\Component\Security\Http\HttpEncodingException;
use Silex\Component\Security\Core\Encoder\TokenEncoderInterface;
use Symfony\Component\HttpFoundation\File\Exception\AccessDeniedException;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

use Junker\Silex\Security\Http\Token\FacebookCanvasToken;


class FacebookCanvasListener implements ListenerInterface {

	const PARAM_NAME = 'signed_request';

	/**
	 * @var TokenStorageInterface
	 */
	protected $securityContext;
	/**
	 * @var AuthenticationManagerInterface
	 */
	protected $authenticationManager;
	/**
	 * @var array
	 */
	protected $options;
	/**
	 * @var string
	 */
	protected $providerKey;



	public function __construct(TokenStorageInterface $securityContext,
								AuthenticationManagerInterface $authenticationManager,
								$providerKey)
	{
		$this->securityContext = $securityContext;
		$this->authenticationManager = $authenticationManager;
		$this->providerKey = $providerKey;
	}
	/**
	 * This interface must be implemented by firewall listeners.
	 *
	 * @param GetResponseEvent $event
	 */
	public function handle(GetResponseEvent $event)
	{
		$request = $event->getRequest();

		if ($signed_request = $this->getSignedRequest($request))
		{
			try {

				$token = new FacebookCanvasToken($signed_request, $this->providerKey);

				$token->signedRequest = $signed_request; 

				$authToken = $this->authenticationManager->authenticate($token);

				$this->securityContext->setToken($authToken);
			} catch (HttpEncodingException $e) {
			} catch (\UnexpectedValueException $e) {
			}
		}
	}

	private function getSignedRequest($request)
	{
		if ($request->query->has(self::PARAM_NAME))
			return $request->query->get(self::PARAM_NAME);

		if ($request->request->has(self::PARAM_NAME))
			return $request->request->get(self::PARAM_NAME);

		return false;
	}
}