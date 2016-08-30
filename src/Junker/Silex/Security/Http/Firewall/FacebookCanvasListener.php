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

	protected $dispatcher;



	public function __construct(TokenStorageInterface $securityContext,	AuthenticationManagerInterface $authenticationManager, EventDispatcherInterface $dispatcher, $appSecret)
	{
		$this->securityContext = $securityContext;
		$this->authenticationManager = $authenticationManager;
		$this->dispatcher = $dispatcher;
		$this->appSecret = $appSecret;
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

			$fb_data = $this->parseSignedRequest($signed_request); 

			$currentToken = $this->securityContext->getToken();

			if ($currentToken instanceof FacebookCanvasToken && is_array($fb_data) && isset($fb_data['user_id']) && $currentToken->fbUid == $fb_data['user_id']) {
				return;
			}

			try {
				$token = new FacebookCanvasToken($signed_request);

				if (is_array($fb_data) && isset($fb_data['user_id']))
					$token->fbUid = $fb_data['user_id'];

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


	private function parseSignedRequest($signed_request) {
	  	list($encoded_sig, $payload) = explode('.', $signed_request, 2); 

		// decode the data
		$sig = self::base64_url_decode($encoded_sig);
		$data = json_decode(self::base64_url_decode($payload), true);

		// confirm the signature
		$expected_sig = hash_hmac('sha256', $payload, $this->appSecret, $raw = true);

		if ($sig !== $expected_sig) {
			return false;
		}

		return $data;
	}

	private static function base64_url_decode($input) {
	  	return base64_decode(strtr($input, '-_', '+/'));
	}
}