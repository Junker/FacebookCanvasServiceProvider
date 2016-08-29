<?php
namespace AimDate\FacebookCanvas\Provider;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Silex\Component\Security\Http\Authentication;

use AimDate\FacebookCanvas\Security\Http\EntryPoint\FacebookCanvasAuthenticationEntryPoint;
use AimDate\FacebookCanvas\Security\Http\Authentication\Provider\FacebookCanvasProvider;
use AimDate\FacebookCanvas\Security\Http\Firewall\FacebookCanvasListener;



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

				$app['security.authentication_listener.'.$full_name] = function() use ($app) {
					return new FacebookCanvasListener($app['security.token_storage'],
						$app['security.authentication_manager'],
						self::PROVIDER_KEY
					);
				};

				$app['security.authentication_provider.'.$full_name] = function() use ($app, $name, $options) {
					return new FacebookCanvasProvider($app['security.user_provider.'.$name], $app['security.user_checker'], self::PROVIDER_KEY, $options['app_secret']);
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