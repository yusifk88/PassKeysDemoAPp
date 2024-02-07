<?php

namespace App\Http\Controllers;

use App\Models\Authenticator;
use App\Models\User;
use App\respositories\CredentialSourceRepository;
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
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

class AuthenticationsController extends Controller implements PublicKeyCredentialSourceRepository
{

    const CREDENTIAL_REQUEST_OPTIONS_SESSION_KEY = 'publicKeyCredentialRequestOptions';


    public function register(Request $request)
    {
        $request->validate([
            "userName" => "required",
            "name" => "required"
        ]);


        $user = User::create([
            "email" => $request->userName,
            "name" => $request->name,
            "password" => Hash::make(Str::password(16))
        ]);

        return \response()->json($user);

    }


    public function makeOptions(Request $request)
    {
        $request->validate([
            "userName" => "required"
        ]);


        $user = User::where("email", $request->userName)->first();

        /**
         * early return if user not found
         */

        if (!$user) {

            return response("User not found", Response::HTTP_UNAUTHORIZED);
        }

        /**
         * create the webauthn user entity
         */

        $userEntity = PublicKeyCredentialUserEntity::create(
            $user->email,
            (string)$user->id,
            $user->email);


        $registeredAuthenticators = $this->findAllForUserEntity($userEntity);


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

       $request->session()->put(self::CREDENTIAL_REQUEST_OPTIONS_SESSION_KEY, $serailizedOptions);


        return $serailizedOptions;

    }



    public function verify(Request $request, ServerRequestInterface $serverRequest): array
    {
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
                session(self::CREDENTIAL_REQUEST_OPTIONS_SESSION_KEY)
            ),
            $serverRequest,
            $authenticatorAssertionResponse->getUserHandle(),
        );

        // If we've gotten this far, the response is valid!

        // We don't need the options anymore, so let's remove them from the session
        $request->session()->forget(self::CREDENTIAL_REQUEST_OPTIONS_SESSION_KEY);

        $user = User::where('username', $publicKeyCredentialSource->getUserHandle())->firstOrFail();

        Auth::login($user);

        return [
            'verified' => true,
        ];
    }



    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return User::with('authenticators')
            ->where("id", $publicKeyCredentialUserEntity->getId())
            ->first()
            ->authenticators
            ->toArray();

    }

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
