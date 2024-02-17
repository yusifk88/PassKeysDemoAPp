<?php

namespace App\respositories;

use App\Models\User;
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
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

class PassKeyAuthRepository
{


    /**
     * @param Request $request
     * @param ServerRequestInterface $serverRequest
     * @return true[]
     * @throws ValidationException
     * @throws \Throwable
     * @throws \Webauthn\Exception\InvalidDataException
     */
    public static function verify(Request $request, ServerRequestInterface $serverRequest){

        // A repo of our public key credentials
        $pkSourceRepo = new CredentialSourceRepository();

        $attestationManager = AttestationStatementSupportManager::create();
        $attestationManager->add(NoneAttestationStatementSupport::create());

        $algorithmManager = Manager::create()->add(
            ES256::create(),
            ES256K::create(),
            ES384::create(),
            ES512::create(),
            RS256::create(),
            RS384::create(),
            RS512::create(),
            PS256::create(),
            PS384::create(),
            PS512::create(),
            Ed256::create(),
            Ed512::create(),
        );

        // The validator that will check the response from the device
        $responseValidator = AuthenticatorAssertionResponseValidator::create(
            $pkSourceRepo,
            IgnoreTokenBindingHandler::create(),
            ExtensionOutputCheckerHandler::create(),
            $algorithmManager,
        );

        // A loader that will load the response from the device
        $pkCredentialLoader = PublicKeyCredentialLoader::create(
            AttestationObjectLoader::create($attestationManager)
        );

        $publicKeyCredential = $pkCredentialLoader->load(json_encode($request->all()));

        $authenticatorAssertionResponse = $publicKeyCredential->getResponse();

        if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
            throw ValidationException::withMessages([
                'username' => 'Invalid response type',
            ]);
        }

        // Check the response from the device, this will
        // throw an exception if the response is invalid.
        // For the purposes of this demo, we are letting
        // the exception bubble up so we can see what is
        // going on.
        $publicKeyCredentialSource = $responseValidator->check(
            $publicKeyCredential->getRawId(),
            $authenticatorAssertionResponse,
            PublicKeyCredentialRequestOptions::createFromArray(
                session(PasskeyConstants::CREDENTIAL_CREATION_OPTIONS_SESSION_KEY)
            ),
            $serverRequest,
            $authenticatorAssertionResponse->getUserHandle(),
        );

        // If we've gotten this far, the response is valid!

        // We don't need the options anymore, so let's remove them from the session
        $request->session()->forget(PasskeyConstants::CREDENTIAL_CREATION_OPTIONS_SESSION_KEY);

        $user = User::where('email', $publicKeyCredentialSource->getUserHandle())->firstOrFail();

        Auth::login($user);

        return [
            'verified' => true,
        ];
    }



    /**
     * @param User $user
     * @return mixed[]
     * @throws Exception
     */

    public static function makeOptions(User $user): array
    {


        $userEntity = PublicKeyCredentialUserEntity::create(
            $user->email,
            (string)$user->id,
            $user->email);


        $registeredAuthenticators = self::findAllForUserEntity($userEntity);


        $allowedCredentials = collect($registeredAuthenticators)
            ->pluck('public_key')
            ->map(
                fn($publicKey) => PublicKeyCredentialSource::createFromArray($publicKey)
            )
            ->map(
                fn(PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor()
            )
            ->toArray();


        $publicKeyoptions = PublicKeyCredentialRequestOptions::create(random_bytes(32))
            ->allowCredentials(...$allowedCredentials);


        $serailizedOptions = $publicKeyoptions->jsonSerialize();


        /**
         * setup the session for the auth device
         */

        request()->session()->put(PasskeyConstants::CREDENTIAL_CREATION_OPTIONS_SESSION_KEY, $serailizedOptions);


        return $serailizedOptions;
    }


    /**
     * @param PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity
     * @return array
     */

    public static function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return User::with('authenticators')
            ->where("id", $publicKeyCredentialUserEntity->getId())
            ->first()
            ->authenticators
            ->toArray();

    }

}
