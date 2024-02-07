<?php

namespace App\Http\Controllers;

use Corbado\Config;
use Corbado\SDK;
use Illuminate\Http\Request;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

class AuthController extends Controller
{
    public function confirmPassKey()
    {

        $projectID = "pro-6839374550780478234";
        $apiSecret = "corbado1_HeRN5X6lCGceFMJVRnsJLnU9RYYfsw";

        $jwksCache = new FilesystemAdapter();

        $config = new Config($projectID, $apiSecret);
        $config->setJwksCachePool($jwksCache);
        $corbado = new SDK($config);
        $corbado = new SDK($config);
        $user = $corbado->sessions()->getCurrentUser();

        dd($user);
    }
}
