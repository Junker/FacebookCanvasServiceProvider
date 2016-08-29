<?php
namespace Junker\Silex\Provider;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Silex\Component\Security\Http\Authentication;

use Junker\Silex\Security\Http\EntryPoint\FacebookCanvasAuthenticationEntryPoint;
use Junker\Silex\Security\Http\Authentication\Provider\FacebookCanvasProvider;
use Junker\Silex\Security\Http\Firewall\FacebookCanvasListener;



class FacebookCanvasServiceProvider implements ServiceProviderInterface
{
	const PROVIDER_KEY = 'facebook_canvas';

	public function register(Application $app)
	{
		
		$app['security.authentication_listener.factory.'.self::PROVIDER_KEY] = $app->protect(function ($name, $options) use ($app) {

				$full_name = $name.'.'.self::PROVIDER_KEY;

				$app['security.entry_point.'.$full_name] = function() use ($app, $options) {
				    return new FacebookCanvasAuthenticationEntryPoint($app, $app['security.http_utils'], $options['login_path']);
				};

				$app['security.authentication_listener.'.$full_name] = function() use ($app, $options) {
					return new FacebookCanvasListener($app['security.token_storage'],
						$app['security.authentication_manager'],
						$app['dispatcher'],
						self::PROVIDER_KEY,
						$options['app_secret']
					);
				};

				$app['security.authentication_provider.'.$full_name] = function() use ($app, $name) {
					return new FacebookCanvasProvider($app['security.user_provider.'.$name], $app['security.user_checker'], self::PROVIDER_KEY);
				};

				return array(
					'security.authentication_provider.'.$full_name,
					'security.authentication_listener.'.$full_name,
					'security.entry_point.'.$full_name,
					'pre_auth'
				);
		});
	}

	public function boot(Application $app)
	{
	}
}