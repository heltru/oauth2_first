<?php
namespace app\modules\oauth2;

class Request{

    public function query($name, $default = null)
    {

        return isset($_REQUEST[$name]) && ($_REQUEST[$name]) ? isset($_REQUEST[$name]) : $default;
    }



    public function request($name, $default = null)
    {
        return isset($_REQUEST[$name]) && ($_REQUEST[$name]) ? isset($_REQUEST[$name]) : $default;
    }

    public function server($name, $default = null)
    {
        return isset($_SERVER[$name]) ? $_SERVER[$name] : $default;
    }

    public function headers($name, $default = null)
    {
        return $this->request->headers->get($name, $default);
    }

    public function getAllQueryParameters()
    {
        return $this->request->queryParams;
    }



}