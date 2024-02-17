<?php

namespace App\Http\Controllers;

use App\Models\Authenticator;
use App\Models\User;
use App\respositories\CredentialSourceRepository;
use App\respositories\PassKeyAuthRepository;
use App\respositories\PasskeyConstants;
use App\respositories\PassKeyRegisterRepository;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

class AuthenticationsController extends Controller
{


    public function makeOptions(Request $request)
    {
        $request->validate([
            "email" => "required"
        ]);


        $user = User::where("email", $request->email)->first();

        /**
         * early return if user not found
         */

        if (!$user) {

            return response("User not found", Response::HTTP_UNAUTHORIZED);
        }

        /**
         * create the webauthn user entity
         */

        return PassKeyAuthRepository::makeOptions($user);

    }


    /**
     * @throws InvalidDataException
     * @throws Throwable
     * @throws ValidationException
     */
    public function verify(Request $request, ServerRequestInterface $serverRequest): array
    {
        return PassKeyAuthRepository::verify($request, $serverRequest);
    }


    /**
     * @param string $publicKeyCredentialId
     * @return PublicKeyCredentialSource|null
     * @throws InvalidDataException
     */

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $auth = Authenticator::where("credential_id", base64_encode($publicKeyCredentialId))->first();

        if (!$auth) {
            return null;
        }

        return PublicKeyCredentialSource::createFromArray($auth->public_key);

    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $user = User::where("email", $publicKeyCredentialSource->getUserHandle())
            ->firstOrFail();


        $user->authenticators->creatt([
            "credential_id" => $publicKeyCredentialSource->publicKeyCredentialId,
            "public_key" => $publicKeyCredentialSource->jsonSerialize()
        ]);


    }


}
