<?php
namespace app\modules\oauth2;

class AuthorizationCode {

    public $storage;
    public $authCode;


    public function __construct($storage)
    {
        $this->storage = $storage;
    }


    public function getQueryStringIdentifier()
    {
        return 'authorization_code';
    }

    /**
     * Validate the OAuth request

     * @return bool
     * @throws Exception
     */
    public function validateRequest( $request,  $response)
    {

        if (!$request->request('code')) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "code" is required');

            return false;
        }

        $code = $request->request('code');
        if (!$authCode = $this->storage->getAuthorizationCode($code)) {
            $response->setError(400, 'invalid_grant', 'Authorization code doesn\'t exist or is invalid for the client');

            return false;
        }

        /*
         * 4.1.3 - ensure that the "redirect_uri" parameter is present if the "redirect_uri" parameter was included in the initial authorization request
         * @uri - http://tools.ietf.org/html/rfc6749#section-4.1.3
         */
        if (isset($authCode['redirect_uri']) && $authCode['redirect_uri']) {
            if (!$request->request('redirect_uri') || urldecode($request->request('redirect_uri')) != urldecode($authCode['redirect_uri'])) {
                $response->setError(400, 'redirect_uri_mismatch', "The redirect URI is missing or do not match", "#section-4.1.3");

                return false;
            }
        }

        if (!isset($authCode['expires'])) {
            throw new \Exception('Storage must return authcode with a value for "expires"');
        }

        if ($authCode["expires"] < time()) {
            $response->setError(400, 'invalid_grant', "The authorization code has expired");

            return false;
        }

        if (!isset($authCode['code'])) {
            $authCode['code'] = $code; // used to expire the code after the access token is granted
        }

        $this->authCode = $authCode;

        return true;
    }

    /**
     * Get the client id
     *
     * @return mixed
     */
    public function getClientId()
    {
        return $this->authCode['client_id'];
    }

    /**
     * Get the scope
     *
     * @return string
     */
    public function getScope()
    {
        return isset($this->authCode['scope']) ? $this->authCode['scope'] : null;
    }

    public function createAccessToken($accessToken, $client_id, $user_id, $scope)
    {

        $token = $accessToken->createAccessToken($client_id, $user_id, $scope);
        $this->storage->expireAuthorizationCode($this->authCode['code']);

        return $token;
    }

}