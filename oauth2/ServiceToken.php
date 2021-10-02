<?php


namespace app\modules\oauth2;

//sernler.ru/oauth2/token
class Token
{

    private $grantTypes  = [];
    private $config = [];

    public $storage = null;

    public $clientData;

    protected function getDefaultTokenType()
    {
        $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_param_name token_bearer_header_name')));

        return new Bearer($config);
    }

    protected function createDefaultAccessTokenResponseType()
    {
        if (!isset($this->storages['access_token'])) {
            throw new \Exception("You must supply a response type implementing OAuth2\ResponseType\AccessTokenInterface, or a storage object implementing OAuth2\Storage\AccessTokenInterface to use the token server");
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'access_lifetime refresh_token_lifetime')));
        $config['token_type'] = $this->tokenType ? $this->tokenType->getTokenType() :  $this->getDefaultTokenType()->getTokenType();

        $refreshStorage = $this->storage;

        return new AccessToken($this->storage, $refreshStorage, $config);
    }

    public function __construct(  $storage,  $config)
    {
        $this->config = array_merge(array(
            'allow_credentials_in_request_body' => true,
            'allow_public_clients' => true,
            'access_lifetime' => 333,
            'refresh_token_lifetime' => 222,
            'token_param_name' => '',
            'token_bearer_header_name' => '',
        ), $config);

        $this->request = new Request();
        $this->responce = new Response();

        $this->storage = new Storage();

        $this->accessToken = $this->createDefaultAccessTokenResponseType();
        $this->storage = $storage;

        $this->addGrantType(new AuthorizationCode($this->storage));


        $this->scopeUtil =  new Scope();
        


    }

    public function begin(){

        $request = $this->request;
        $response = $this->responce;

        if ($token = $this->grantAccessToken($request, $response)) {
            // @see http://tools.ietf.org/html/rfc6749#section-5.1
            // server MUST disable caching in headers when tokens are involved
            $response->setStatusCode(200);
            $response->addParameters($token);
            $response->addHttpHeaders(array(
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'Content-Type' => 'application/json'
            ));
        }
    }

    public function grantAccessToken( $request,  $response)
    {

        if (strtolower($request->server('REQUEST_METHOD')) === 'options') {
            $response->addHttpHeaders(array('Allow' => 'POST, OPTIONS'));

            return null;
        }

        if (strtolower($request->server('REQUEST_METHOD')) !== 'post') {
            $response->setError(405, 'invalid_request', 'The request method must be POST when requesting an access token', '#section-3.2');
            $response->addHttpHeaders(array('Allow' => 'POST, OPTIONS'));

            return null;
        }

        /**
         * Determine grant type from request
         * and validate the request for that grant type
         */
        if (!$grantTypeIdentifier = $request->request('grant_type')) {
            $response->setError(400, 'invalid_request', 'The grant type was not specified in the request');

            return null;
        }


        if (!isset($this->grantTypes[$grantTypeIdentifier])) {
            /* TODO: If this is an OAuth2 supported grant type that we have chosen not to implement, throw a 501 Not Implemented instead */
            $response->setError(400, 'unsupported_grant_type', sprintf('Grant type "%s" not supported', $grantTypeIdentifier));

            return null;
        }


        $grantType = $this->grantTypes[$grantTypeIdentifier];


        if (!$this->validateRequest($request, $response)) { //записывает   $this->clientData
            return null;
        }
        $clientId = $this->getClientId();

        /**
         * Retrieve the grant type information from the request
         * The GrantTypeInterface object handles all validation
         * If the object is an instance of ClientAssertionTypeInterface,
         * That logic is handled here as well
         */
        if (!$grantType->validateRequest($request, $response)) {
            return null;
        }

        // validate the Client ID (if applicable)
        if (!is_null($storedClientId = $grantType->getClientId()) && $storedClientId != $clientId) {
            $response->setError(400, 'invalid_grant', sprintf('%s doesn\'t exist or is invalid for the client', $grantTypeIdentifier));

            return null;
        }

        /**
         * Validate the client can use the requested grant type
         */
        if (!$this->storage->checkRestrictedGrantType($clientId, $grantTypeIdentifier)) {
            $response->setError(400, 'unauthorized_client', 'The grant type is unauthorized for this client_id');

            return false;
        }

        /**
         * Validate the scope of the token
         *
         * requestedScope - the scope specified in the token request
         * availableScope - the scope associated with the grant type
         *  ex: in the case of the "Authorization Code" grant type,
         *  the scope is specified in the authorize request
         *
         * @see http://tools.ietf.org/html/rfc6749#section-3.3
         */
        $requestedScope = $this->scopeUtil->getScopeFromRequest($request);
        $availableScope = $grantType->getScope();

        if ($requestedScope) {
            // validate the requested scope
            if ($availableScope) {
                if (!$this->scopeUtil->checkScope($requestedScope, $availableScope)) {
                    $response->setError(400, 'invalid_scope', 'The scope requested is invalid for this request');

                    return null;
                }
            } else {
                // validate the client has access to this scope
                if ($clientScope = $this->storage->getClientScope($clientId)) {
                    if (!$this->scopeUtil->checkScope($requestedScope, $clientScope)) {
                        $response->setError(400, 'invalid_scope', 'The scope requested is invalid for this client');

                        return false;
                    }
                } elseif (!$this->scopeUtil->scopeExists($requestedScope)) {
                    $response->setError(400, 'invalid_scope', 'An unsupported scope was requested');

                    return null;
                }
            }
        } elseif ($availableScope) {
            // use the scope associated with this grant type
            $requestedScope = $availableScope;
        } else {
            // use a globally-defined default scope
            $defaultScope = $this->scopeUtil->getDefaultScope($clientId);

            // "false" means default scopes are not allowed
            if (false === $defaultScope) {
                $response->setError(400, 'invalid_scope', 'This application requires you specify a scope parameter');

                return null;
            }

            $requestedScope = $defaultScope;
        }


        return $grantType->createAccessToken($this->accessToken, $clientId, $grantType->getUserId(), $requestedScope);
    }

    /**
     * Add grant type
     *
     * @param  $grantType  - the grant type to add for the specified identifier
     * @param string|null        $identifier - a string passed in as "grant_type" in the response that will call this grantType
     */
    public function addGrantType( $grantType, $identifier = null)
    {
        if (is_null($identifier) || is_numeric($identifier)) {
            $identifier = $grantType->getQueryStringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
    }

    public function validateRequest( $request,  $response)
    {

        if (!$clientData = $this->getClientCredentials($request, $response)) {
            return false;
        }

        if (!isset($clientData['client_id'])) {
            throw new \Exception('the clientData array must have "client_id" set');
        }

        if (!isset($clientData['client_secret']) || $clientData['client_secret'] == '') {
            if (!$this->config['allow_public_clients']) {
                $response->setError(400, 'invalid_client', 'client credentials are required');

                return false;
            }

            if (!$this->storage->isPublicClient($clientData['client_id'])) {
                $response->setError(400, 'invalid_client', 'This client is invalid or must authenticate using a client secret');

                return false;
            }
        } elseif ($this->storage->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $response->setError(400, 'invalid_client', 'The client credentials are invalid');

            return false;
        }

        $this->clientData = $clientData;

        return true;
    }

    public function getClientCredentials( $request,  $response = null)
    {
        // Using POST for HttpBasic authorization is not recommended, but is supported by specification
        if (!is_null($request->request('client_id'))) {
            /**
             * client_secret can be null if the client's password is an empty string
             * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
             */
            return array('client_id' => $request->request('client_id'), 'client_secret' => $request->request('client_secret'));
        }
      
        return null;
    }

    /**
     * Get the client id
     *
     * @return mixed
     */
    public function getClientId()
    {
        return $this->clientData['client_id'];
    }


}