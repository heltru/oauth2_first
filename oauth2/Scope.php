<?php


namespace app\modules\oauth2;


class Scope
{
    public function getScopeFromRequest($request)//Request
    {
        // "scope" is valid if passed in either POST or QUERY
        return $request->request('scope');
    }


    public function scopeExists($scope)
    {
        // Check reserved scopes first.
        $scope = explode(' ', trim($scope));
        $reservedScope = $this->getReservedScopes();
        $nonReservedScopes = array_diff($scope, $reservedScope);
        if (count($nonReservedScopes) == 0) {
            return true;
        } else {
            // Check the storage for non-reserved scopes.
            $nonReservedScopes = implode(' ', $nonReservedScopes);

            return $this->storage->scopeExists($nonReservedScopes);
        }
    }

    /**
     * Get reserved scopes needed by the server.
     *
     * In case OpenID Connect is used, these scopes must include:
     * 'openid', offline_access'.
     *
     * @return array - An array of reserved scopes.
     */
    public function getReservedScopes()
    {
        return array('openid', 'offline_access');
    }

    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param string $required_scope  - A space-separated string of scopes.
     * @param string $available_scope - A space-separated string of scopes.
     * @return bool                   - TRUE if everything in required scope is contained in available scope and FALSE
     *                                  if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function checkScope($required_scope, $available_scope)
    {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    /**
     * @param null $client_id
     * @return mixed
     */
    public function getDefaultScope($client_id = null)
    {
        return 'delivery bot lead subscription lead_stat delivery_stat global_vars process utms';
    }



}