# FacebookCanvasServiceProvider
Facebook Canvas Service Provider for Silex

## Requirements
silex 1.x

##Installation
The best way to install FacebookCanvasServiceProvider is to use a [Composer](https://getcomposer.org/download):

    php composer.phar require junker/facebook-canvas-service-provider

## Examples

```php
use Junker\Silex\Provider\FacebookCanvasServiceProvider;

$app['users'] = $app->share(function() use ($app) { return new MyApp\UserProvider($app['db']); });

$app['security.firewalls'] =  [
	'fb_canvas' => [		
			'pattern' => '^/fb_canvas/',
			'users' => $app['users'],
			'anonymous' => true,
			'facebook_canvas' => [
				'login_path' => '/registration',
				'app_secret' => $facebook_app_secret
			]
	],
];

```


UserProvider Must implements FacebookCanvasUserProviderInterface

```php

<?php
namespace MyApp;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;

use Junker\Silex\Security\User\FacebookCanvasUserProviderInterface;

class UserProvider implements UserProviderInterface,FacebookCanvasUserProviderInterface
{
	private $db;

	public function __construct($db)
	{
		$this->db = $db;
	}
 
	public function loadUserByFacebookUid($fbUid)
	{
		$username = $this->db->fetchColumn('SELECT username FROM user WHERE facebook_uid=?', [$fbUid]);

		return $this->loadUserByUsername($username);
	}

	....
}
```
