<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\respositories\CredentialSourceRepository;
use Cose\Algorithms;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\Util\Base64;

class RegisterController extends Controller
{
    // We use this key across several methods, so we're going to define it here
    const CREDENTIAL_CREATION_OPTIONS_SESSION_KEY = 'publicKeyCredentialCreationOptions';

    /**
     * @throws InvalidDataException
     */
    public function generateOptions(Request $request): array
    {

        $request->validate([
            "userName" => "required",
            "name" => "required"
        ]);

        // Relying Party Entity i.e. the application
        $rpEntity = PublicKeyCredentialRpEntity::create(
            config('app.name'),
            parse_url(config('app.url'), PHP_URL_HOST),
            null,
        );

        $userName = $request->userName;
        // User Entity
        $userEntity = PublicKeyCredentialUserEntity::create(
            $request->name,
            Base64UrlSafe::encodeUnpadded($userName),
            $userName,
            null,
        );

        // Challenge (random binary string)
        $challenge = random_bytes(32);

        // List of supported public key parameters
        $supportedPublicKeyParams = collect([
            Algorithms::COSE_ALGORITHM_ES256,
            Algorithms::COSE_ALGORITHM_ES256K,
            Algorithms::COSE_ALGORITHM_ES384,
            Algorithms::COSE_ALGORITHM_ES512,
            Algorithms::COSE_ALGORITHM_RS256,
            Algorithms::COSE_ALGORITHM_RS384,
            Algorithms::COSE_ALGORITHM_RS512,
            Algorithms::COSE_ALGORITHM_PS256,
            Algorithms::COSE_ALGORITHM_PS384,
            Algorithms::COSE_ALGORITHM_PS512,
            Algorithms::COSE_ALGORITHM_ED256,
            Algorithms::COSE_ALGORITHM_ED512,
        ])->map(
            fn($algorithm) => PublicKeyCredentialParameters::create('public-key', $algorithm)
        )->toArray();

        // Instantiate PublicKeyCredentialCreationOptions object
        $pkCreationOptions =
            PublicKeyCredentialCreationOptions::create(
                $rpEntity,
                $userEntity,
                $challenge,
                $supportedPublicKeyParams,
            )
                ->setAttestation(
                    PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE
                )
                ->setAuthenticatorSelection(
                    AuthenticatorSelectionCriteria::create()
                )
                ->setExtensions(AuthenticationExtensionsClientInputs::createFromArray([
                    'credProps' => true,
                ]));

        $serializedOptions = $pkCreationOptions->jsonSerialize();


        if (!isset($serializedOptions['excludeCredentials'])) {
            // The JS side needs this, so let's set it up for success with an empty array
            $serializedOptions['excludeCredentials'] = [];
        }

        // This library for some reason doesn't serialize the extensions object,
        // so we'll do it manually
        $serializedOptions['extensions'] = $serializedOptions['extensions']->jsonSerialize();

        // Another thing we have to do manually for this to work the way we want to

        $criteria = AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED;


        $selectionArr = (array)$serializedOptions['authenticatorSelection'];

        $extensions = (array)$serializedOptions['extensions'];
        $user = (array)$serializedOptions['user'];
        $rp = (array)$serializedOptions['rp'];
        $credProps = (array)$extensions["credProps"];

        $publicKeyParams = $serializedOptions['pubKeyCredParams'];

        $paramList = [];

        foreach ($publicKeyParams as $param) {
            $paramList[] = [
                "type" => $param->type,
                "alg" => $param->alg

            ];

        }


        $serializedOptions['pubKeyCredParams'] = $paramList;

        $extensions["credProps"] = $credProps;

        $serializedOptions['rp'] = $rp;
        $serializedOptions['user'] = $user;
        $serializedOptions['extensions'] = $extensions;

        $serializedOptions['authenticatorSelection'] = $selectionArr;

        $serializedOptions['authenticatorSelection']['residentKey'] = $criteria;

        // It is important to store the user entity and the options object in the session
        // for the next step. The data will be needed to check the response from the device.
        $request->session()->put(
            self::CREDENTIAL_CREATION_OPTIONS_SESSION_KEY,
            $serializedOptions
        );

        return $serializedOptions;

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
        // This is a repo of our public key credentials
        $pkSourceRepo = new CredentialSourceRepository();

        $attestationManager = AttestationStatementSupportManager::create();
        $attestationManager->add(NoneAttestationStatementSupport::create());

        // The validator that will check the response from the device
        $responseValidator = AuthenticatorAttestationResponseValidator::create(
            $attestationManager,
            $pkSourceRepo,
            IgnoreTokenBindingHandler::create(),
            ExtensionOutputCheckerHandler::create(),
        );

        // A loader that will load the response from the device
        $pkCredentialLoader = PublicKeyCredentialLoader::create(
            AttestationObjectLoader::create($attestationManager)
        );

        $publicKeyCredential = $pkCredentialLoader->load(json_encode($request->all()));

        $authenticatorAttestationResponse = $publicKeyCredential->getResponse();

        if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
            throw ValidationException::withMessages([
                'username' => 'Invalid response type',
            ]);
        }

        // Check the response from the device, this will
        // throw an exception if the response is invalid.
        // For the purposes of this demo, we are letting
        // the exception bubble up so we can see what is
        // going on.

        $entity = session(self::CREDENTIAL_CREATION_OPTIONS_SESSION_KEY);



        $publicKeyCredentialSource = $responseValidator->check(
            $authenticatorAttestationResponse,
            PublicKeyCredentialCreationOptions::createFromArray($entity),
            $serverRequest
        );


        // If we've gotten this far, the response is valid!

        // We don't need the options anymore, so let's remove them from the session
        $request->session()->forget(self::CREDENTIAL_CREATION_OPTIONS_SESSION_KEY);

        // Save the user and the public key credential source to the database
        $user = User::create([
            'email' => $publicKeyCredentialSource->getUserHandle(),
        ]);

        $pkSourceRepo->saveCredentialSource($publicKeyCredentialSource);

        Auth::login($user);

        return [
            'verified' => true,
        ];
    }

}
