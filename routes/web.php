<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\AuthenticationsController;
use App\Http\Controllers\RegisterController;
use Corbado\Config;
use Corbado\Configuration;
use Corbado\SDK;
use Illuminate\Support\Facades\Route;
use ParagonIE\ConstantTime\Base64UrlSafe;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

//Route::get('/', [AuthController::class, "confirmPassKey"]);

Route::get("/", function () {

    return view("login");

});


Route::post("passkey-auth/options", [AuthenticationsController::class, "makeOptions"]);

Route::post("passkey-auth/register/options", [RegisterController::class, "generateOptions"]);
Route::post("passkey-auth/register/verify", [RegisterController::class, "verify"]);

require __DIR__ . '/auth.php';

