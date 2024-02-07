<?php

use App\Http\Controllers\AuthenticationsController;
use App\Http\Controllers\RegisterController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware(['auth:sanctum'])->get('/user', function (Request $request) {
    return $request->user();
});


Route::post("passkey-auth/options", [AuthenticationsController::class, "makeOptions"]);

Route::post("passkey-auth/register/options", [RegisterController::class, "generateOptions"]);
Route::post("passkey-auth/register/verify", [RegisterController::class, "verify"]);
