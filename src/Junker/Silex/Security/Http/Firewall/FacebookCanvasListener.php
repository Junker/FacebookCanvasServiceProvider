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
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Http\SecurityEvents;
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

	protected $dispatcher;



	public function __construct(TokenStorageInterface $securityContext,	AuthenticationManagerInterface $authenticationManager, EventDispatcherInterface $dispatcher, $providerKey)
	{
		$this->securityContext = $securityContext;
		$this->authenticationManager = $authenticationManager;
		$this->providerKey = $providerKey;
		$this->dispatcher = $dispatcher;
	}


	/**
	 * This interface must be implemented by firewall listeners.
	 *
	 * @param GetResponseEvent $event
	 */
	public function handle(GetResponseEvent $event)
	{
		$request = $event->getRequest();

		if ($signed_request = $this->getSignedRequest($request)) {
			try {

				$token = new FacebookCanvasToken($signed_request, $this->providerKey);

				$token->signedRequest = $signed_request; 

				$authToken = $this->authenticationManager->authenticate($token);

				$this->securityContext->setToken($authToken);

				$loginEvent = new InteractiveLoginEvent($request, $authToken);
				$this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);

			} catch (HttpEncodingException $e) {
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