<?php

namespace Junker\Silex\Security\Http\EntryPoint;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class FacebookCanvasAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
	private $loginPath;
	private $httpKernel;
	private $httpUtils;

	/**
	 * Constructor.
	 *
	 * @param HttpKernelInterface $kernel
	 * @param HttpUtils           $httpUtils  An HttpUtils instance
	 * @param string              $loginPath  The path to the login form
	 */
	public function __construct(HttpKernelInterface $kernel, HttpUtils $httpUtils, $loginPath)
	{
	    $this->httpKernel = $kernel;
	    $this->httpUtils = $httpUtils;
	    $this->loginPath = $loginPath;
	}


	/**
	 * Starts the authentication scheme.
	 *
	 * @param Request                 $request       The request that resulted in an AuthenticationException
	 * @param AuthenticationException $authException The exception that started the authentication process
	 *
	 * @return Response
	 */
	public function start(Request $request, AuthenticationException $authException = null)
	{
		return $this->httpUtils->createRedirectResponse($request, $this->loginPath);
	}
}