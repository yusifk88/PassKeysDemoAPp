<?php

namespace App\Http\Controllers;

use App\respositories\PassKeyRegisterRepository;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\Exception\InvalidDataException;


class RegisterController extends Controller
{

    /**
     * @param Request $request
     * @return array
     * @throws InvalidDataException
     */
    public function generateOptions(Request $request): array
    {

        $request->validate([
            "email" => "required",
            "name" => "required"
        ]);


        return PassKeyRegisterRepository::GenerateOptions($request);

    }



    /**
     * @param Request $request
     * @param ServerRequestInterface $serverRequest
     * @return true[]
     * @throws InvalidDataException
     * @throws ValidationException
     * @throws Throwable
     */

    public function verify(Request $request, ServerRequestInterface $serverRequest): array
    {

        return PassKeyRegisterRepository::verify($request, $serverRequest);

    }

}
