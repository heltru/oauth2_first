<?php

namespace app\modules\oauth2;

//sernler.ru/oauth2/authorize
class ServiceAuthorize
{
    public $errors = [];
    protected $config = [];

    public $storage = null;
    public $request = null;
    public $responce = null;
    public $scopeUtil = null;

    const RESPONSE_TYPE_AUTHORIZATION_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';

    private $scope;
    private $state;
    private $client_id;
    private $redirect_uri;
    private $response_type;


    public function __construct($config = [])
    {
      
        $this->request = new Request();
        $this->responce = new Response();
        $this->storage = new Storage();
        $this->scopeUtil = new Scope();

        $this->config = array_merge(array(
            'allow_implicit' => false,
            'enforce_state'  => true,
            'require_exact_redirect_uri' => true,
            'redirect_status_code' => 302,
        ), $config);
    }

    /*
     * Типа юзер в app.com жмет "войти через senler"
     *
     *  Клиент должен отправить пользователя на authorizeURL-адрес сервера Senler/oauth2/authorize?response_type=code&client_id=testclient&state=user&scope=photo&redirect_uri=http://app.com/callback_senler
     *
     *  Юзер что то подтверждает  и
     */
    /* Выход функции -> Редиректит юзера на callback Интеграции -
    "http://app.com/callback_senler?code=410fba7f5a295369a945727e0d3c1b9f91d6dfcf&state=user"
   */
    public function begin()
    {

        $is_authorized = (Service\Sessions::getAuthUser()) ? true : false; //user дб залогинен в senler
        $user_id = VkSender/Core/App::getUserId(); // authorization_codes привязывается к user_id


        if (!is_bool($is_authorized)) {
            throw new \Exception('Argument "is_authorized" must be a boolean.  This method must know if the user has granted access to the client.');
        }
        $request = $this->request;
        $response = $this->responce;

        //Мы повторяем это, потому что нам нужно повторно проверить. Запрос может быть отправлен на POST
        //третьей стороной (потому что мы не обеспечиваем соблюдение NONCE внутри компании и т. д.)
        if (!$this->validateAuthorizeRequest($request, $response)) {
            return;
        }

        // Если в запросе не передается redirect_uri, используйте зарегистрированный клиентом
        if (empty($this->redirect_uri)) {
            $clientData = $this->storage->getClientDetails($this->client_id);
            $registered_redirect_uri = $clientData['redirect_uri'];
        }

        // пользователь отказался от доступа к клиентскому приложению
        if ($is_authorized === false) {
            $redirect_uri = $this->redirect_uri ?: $registered_redirect_uri;
            $this->setNotAuthorizedResponse($request, $response, $redirect_uri, $user_id);

            return;
        }

        // build the parameters to set in the redirect URI
        if (!$params = $this->buildAuthorizeParameters($request, $response, $user_id)) {
            return;
        }

        $authResult = $this->getAuthorizeResponse($params, $user_id);

        list($redirect_uri, $uri_params) = $authResult;

        if (empty($redirect_uri) && !empty($registered_redirect_uri)) {
            $redirect_uri = $registered_redirect_uri;
        }

        $uri = $this->buildUri($redirect_uri, $uri_params);

        ex($uri);
        $response->setRedirect($this->config['redirect_status_code'], $uri);

    }
 


    public function validateAuthorizeRequest($request, $response)
    {

        // Make sure a valid client id was supplied (we can not redirect because we were unable to verify the URI)
        ;
        if (!$client_id = $request->query('client_id')) {
            // We don't have a good URI to use

            $response->addHttpHeaders(400, 'invalid_client', "No client id supplied");

            return false;
        }

        // Get client details
        if (!$clientData = $this->storage->getClientDetails($client_id)) {
            $response->addHttpHeaders(400, 'invalid_client', 'The client id supplied is invalid');

            return false;
        }

        $registered_redirect_uri = isset($clientData['redirect_uri']) ? $clientData['redirect_uri'] : '';

        // Make sure a valid redirect_uri was supplied. If specified, it must match the clientData URI.
        // @see http://tools.ietf.org/html/rfc6749#section-3.1.2
        // @see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
        // @see http://tools.ietf.org/html/rfc6749#section-4.2.2.1

        if ($supplied_redirect_uri = $request->query('redirect_uri')) {
            // validate there is no fragment supplied
            $parts = parse_url($supplied_redirect_uri);

            if (isset($parts['fragment']) && $parts['fragment']) {
                $response->addHttpHeaders(400, 'invalid_uri', 'The redirect URI must not contain a fragment');

                return false;
            }

            // validate against the registered redirect uri(s) if available
            if ($registered_redirect_uri && !$this->validateRedirectUri($supplied_redirect_uri, $registered_redirect_uri)) {
                $response->addHttpHeaders(400, 'redirect_uri_mismatch', 'The redirect URI provided is missing or does not match', '#section-3.1.2');

                return false;
            }
            $redirect_uri = $supplied_redirect_uri;

        } else {
            // use the registered redirect_uri if none has been supplied, if possible
            if (!$registered_redirect_uri) {
                $response->addHttpHeaders(400, 'invalid_uri', 'No redirect URI was supplied or stored');

                return false;
            }

            if (count(explode(' ', $registered_redirect_uri)) > 1) {
                $response->addHttpHeaders(400, 'invalid_uri', 'A redirect URI must be supplied when multiple redirect URIs are registered', '#section-3.1.2.3');

                return false;
            }
            $redirect_uri = $registered_redirect_uri;
        }

        // Select the response type
        $response_type = $request->query('response_type');

        // for multiple-valued response types - make them alphabetical
        if (false !== strpos($response_type, ' ')) {
            $types = explode(' ', $response_type);
            sort($types);
            $response_type = ltrim(implode(' ', $types));
        }

        $state = $request->query('state');

        // type and client_id are required
        if (!$response_type || !in_array($response_type, $this->getValidResponseTypes())) {
            $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_request', 'Invalid or missing response type', null);

            return false;
        }

        if ($response_type == self::RESPONSE_TYPE_AUTHORIZATION_CODE) {

            if (!isset($this->responseTypes['code'])) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'unsupported_response_type', 'authorization code grant type not supported', null);

                return false;
            }

            if (!$this->storage->checkRestrictedGrantType($client_id, 'authorization_code')) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'unauthorized_client', 'The grant type is unauthorized for this client_id', null);

                return false;
            }

            if ( !$redirect_uri) {
                $response->addHttpHeaders(400, 'redirect_uri_mismatch', 'URI перенаправления является обязательным и не был предоставлен');

                return false;
            }
        }

        // validate requested scope if it exists
        $requestedScope = $this->scopeUtil->getScopeFromRequest($request);

        if ($requestedScope) {
            // restrict scope by client specific scope if applicable,
            // otherwise verify the scope exists
            $clientScope = $this->storage->getClientScope($client_id);

            if ((empty($clientScope) && !$this->scopeUtil->scopeExists($requestedScope))
                || (!empty($clientScope) && !$this->scopeUtil->checkScope($requestedScope, $clientScope))) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_scope', 'An unsupported scope was requested', null);

                return false;
            }
        } else {
            // use a globally-defined default scope
            $defaultScope = $this->scopeUtil->getDefaultScope($client_id);

            if (false === $defaultScope) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_client', 'This application requires you specify a scope parameter', null);

                return false;
            }

            $requestedScope = $defaultScope;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, null, 'invalid_request', 'The state parameter is required');

            return false;
        }

        // save the input data and return true
        $this->scope = $requestedScope;
        $this->state = $state;
        $this->client_id = $client_id;
        // Only save the SUPPLIED redirect URI (@see http://tools.ietf.org/html/rfc6749#section-4.1.3)
        $this->redirect_uri = $supplied_redirect_uri;
        $this->response_type = $response_type;

        return true;
    }


    /**
     * Internal method for validating redirect URI supplied
     *
     * @param string $inputUri The submitted URI to be validated
     * @param string $registeredUriString The allowed URI(s) to validate against.  Can be a space-delimited string of URIs to
     *                                    allow for multiple URIs
     * @return bool
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     */
    private function validateRedirectUri($inputUri, $registeredUriString){
        if (!$inputUri || !$registeredUriString) {
            return false; // if either one is missing, assume INVALID
        }

        $registered_uris = preg_split('/\s+/', $registeredUriString);
        foreach ($registered_uris as $registered_uri) {

            if ($this->config['require_exact_redirect_uri']) {
                // the input uri is validated against the registered uri using exact match
                if (strcmp($inputUri, $registered_uri) === 0) {
                    return true;
                }
            } else {
                $registered_uri_length = strlen($registered_uri);
                if ($registered_uri_length === 0) {
                    return false;
                }

                // the input uri is validated against the registered uri using case-insensitive match of the initial string
                // i.e. additional query parameters may be applied
                if (strcasecmp(substr($inputUri, 0, $registered_uri_length), $registered_uri) === 0) {
                    return true;
                }
            }
        }

        return false;
    }


    protected function getValidResponseTypes()
    {
        return array(
            self::RESPONSE_TYPE_ACCESS_TOKEN,
            self::RESPONSE_TYPE_AUTHORIZATION_CODE,
        );
    }

    protected function setNotAuthorizedResponse( $request,  $response, $redirect_uri, $user_id = null)
    {
        $error = 'access_denied';
        $error_message = 'The user denied access to your application';
        $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $this->state, $error, $error_message);
    }

    protected function buildAuthorizeParameters($request, $response, $user_id)
    {
        // @TODO: we should be explicit with this in the future
        $params = array(
            'scope'         => $this->scope,
            'state'         => $this->state,
            'client_id'     => $this->client_id,
            'redirect_uri'  => $this->redirect_uri,
            'response_type' => $this->response_type,
        );

        return $params;
    }


    /////////////////
    public function getAuthorizeResponse($params, $user_id = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null);

        $result['query']['code'] = $this->createAuthorizationCode($params['client_id'], $user_id, $params['redirect_uri'], $params['scope']);

        if (isset($params['state'])) {
            $result['query']['state'] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }
    public function createAuthorizationCode($client_id, $user_id, $redirect_uri, $scope = null)
    {
        $code = $this->generateAuthorizationCode();
        $this->storage->setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, time() + $this->config['auth_code_lifetime'], $scope);

        return $code;
    }
    /**
     * Generates an unique auth code.
     *
     * Implementing classes may want to override this function to implement
     * other auth code generation schemes.
     *
     * @return
     * An unique auth code.
     *
     * @ingroup oauth2_section_4
     */
    protected function generateAuthorizationCode()
    {
        $tokenLen = 40;
        if (function_exists('random_bytes')) {
            $randomData = random_bytes(100);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(100);
        } elseif (function_exists('mcrypt_create_iv')) {
            $randomData = mcrypt_create_iv(100, MCRYPT_DEV_URANDOM);
        } elseif (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }

        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }

    /**
     * Build the absolute URI based on supplied URI and parameters.
     *
     * @param string $uri    An absolute URI.
     * @param array  $params Parameters to be append as GET.
     *
     * @return string
     * An absolute URI with supplied parameters.
     *
     * @ingroup oauth2_section_4
     */
    private function buildUri($uri, $params)
    {
        $parse_url = parse_url($uri);

        // Add our params to the parsed uri
        foreach ($params as $k => $v) {
            if (isset($parse_url[$k])) {
                $parse_url[$k] .= "&" . http_build_query($v, '', '&');
            } else {
                $parse_url[$k] = http_build_query($v, '', '&');
            }
        }

        // Put the uri back together
        return
            ((isset($parse_url["scheme"])) ? $parse_url["scheme"] . "://" : "")
            . ((isset($parse_url["user"])) ? $parse_url["user"]
                . ((isset($parse_url["pass"])) ? ":" . $parse_url["pass"] : "") . "@" : "")
            . ((isset($parse_url["host"])) ? $parse_url["host"] : "")
            . ((isset($parse_url["port"])) ? ":" . $parse_url["port"] : "")
            . ((isset($parse_url["path"])) ? $parse_url["path"] : "")
            . ((isset($parse_url["query"]) && !empty($parse_url['query'])) ? "?" . $parse_url["query"] : "")
            . ((isset($parse_url["fragment"])) ? "#" . $parse_url["fragment"] : "")
            ;
    }

}