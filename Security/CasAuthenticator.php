<?php

namespace L3\Bundle\CasGuardBundle\Security;

use L3\Bundle\CasGuardBundle\Event\CasAuthenticationFailureEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class CasAuthenticator extends AbstractGuardAuthenticator {
    protected $config;
    
    private $eventDispatcher;
    
    /**
     * Process configuration
     * @param array $config
     */
    public function __construct($config, EventDispatcherInterface $eventDispatcher) {
        $this->config = $config;
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     *
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request) {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request) {        
        $user = "__NO_USER__";
        
        if(!isset($_SESSION)) session_start();

        \phpCAS::setDebug(false);

        \phpCAS::client(CAS_VERSION_2_0, $this->getParameter('host'), $this->getParameter('port'), is_null($this->getParameter('path')) ? '' : $this->getParameter('path'), true);

        if(is_bool($this->getParameter('ca')) && $this->getParameter('ca') == false) {
            \phpCAS::setNoCasServerValidation();
        } else {
            \phpCAS::setCasServerCACert($this->getParameter('ca'));
        }

        if($this->getParameter('handleLogoutRequest')) {
            if ($request->request->has('logoutRequest')) {
                $this->checkHandleLogout($request);
            }
            $logoutRequest = $request->request->get('logoutRequest');

            \phpCAS::handleLogoutRequests(true);
        } else {
            \phpCAS::handleLogoutRequests(false);
        }

        
        // si le mode gateway est activé..
        if ($this->getParameter('gateway')) {
            
            // .. code de pierre pelisset (pour les applis existantes...)
            
            if($this->getParameter('force')) {
                \phpCAS::forceAuthentication();
                $user = \phpCAS::getUser();
                //$force = true;
            } else {
                //$force = false;
                //if(!isset($_SESSION['cas_user'])) {
                    $auth = \phpCAS::checkAuthentication();
                    if($auth) {
                        //$_SESSION['cas_user'] = \phpCAS::getUser();
                        $user = \phpCAS::getUser();
                        //$_SESSION['cas_attributes'] = \phpCAS::getAttributes();
                    } else {
                        //$_SESSION['cas_user'] = false;
                        $user = "__NO_USER__";
                    }
                //}
            }
            /*if(!$force) {
                if (!$_SESSION['cas_user']) {
                    $user = "__NO_USER__";
                } else {
                    $user = $_SESSION['cas_user'];
                }
                
            }*/
            
        } else { 
        
            // .. sinon code de david .. pour les api rest / microservices et donc le nouvel ent ulille en view js notamment
            
            if($this->getParameter('force')) {
                \phpCAS::forceAuthentication();
                $user = \phpCAS::getUser();
            } else {
                $authenticated = false;                      
                if($this->getParameter('gateway')) {
                    $authenticated = \phpCAS::checkAuthentication();
                } else {
                    $authenticated = \phpCAS::isAuthenticated();
                }
                
                //if ( (!isset($_SESSION['cas_user'])) || ( (isset($_SESSION['cas_user'])) && ($_SESSION['cas_user'] != false) ) ) {
                    
                    if($authenticated) {
                        //$_SESSION['cas_user'] = \phpCAS::getUser();
                        //$_SESSION['cas_attributes'] = \phpCAS::getAttributes();
                        //$user = $_SESSION['cas_user'];
                        $user = \phpCAS::getUser();
                    } else {
                        $user = "__NO_USER__";
                    }
                //}
            } 
        }
        
        return $user;
    }

    /**
     * Calls the UserProvider providing a valid User
     * @param array $credentials
     * @param UserProviderInterface $userProvider
     * @return bool
     */
    public function getUser($credentials, UserProviderInterface $userProvider) {
        return $userProvider->loadUserByUsername($credentials);        
    }

    /**
     * Mandatory but not in use in a remote authentication
     * @param $credentials
     * @param UserInterface $user
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user) {
        return true;
    }

    /**
     * Mandatory but not in use in a remote authentication
     * @param Request $request
     * @param TokenInterface $token
     * @param $providerKey
     * @return null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey) {
        //if (\phpCAS::isSessionAuthenticated()) {
        //    $token->setAttributes(\phpCAS::getAttributes());
        //}
        if (\phpCAS::isInitialized()) {
    		$authenticated = false;                      
    		if($this->getParameter('gateway')) {
        		$authenticated = \phpCAS::checkAuthentication();
    		} else {
        		$authenticated = \phpCAS::isAuthenticated();
    		}
    
    		if ($authenticated) {                
        		$token->setAttributes(\phpCAS::getAttributes());
    		}            
	}
        
        return null;
    }

    /**
     * Mandatory but not in use in a remote authentication
     * @param Request $request
     * @param AuthenticationException $exception
     * @return Response
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception) {
        //echo "onAuthenticationFailure<br />";
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());
        $def_response = new Response($message, 403);
        
        $event = new CasAuthenticationFailureEvent($request,$exception, $def_response);
        $this->eventDispatcher->dispatch(CasAuthenticationFailureEvent::POST_MESSAGE, $event);

        return $event->getResponse();
    }

    /**
     * Called when authentication is needed, redirect to your CAS server authentication form
     */
    public function start(Request $request, AuthenticationException $authException = null) {
        
    }

    /**
     * Mandatory but not in use in a remote authentication
     * @return bool
     */
    public function supportsRememberMe() {
        return false;
    }

    public function getParameter($key) {
        if(!array_key_exists($key, $this->config)) {
            throw new InvalidConfigurationException('l3_cas_guard.' . $key . ' is not defined');
        }
        return $this->config[$key];
    }
    
    /**
     * Cette fonction sert à vérifier le global logout, PHPCAS n'arrive en effet pas à le gérer étrangement dans Symfony2
     * @param Request $request
     */
    public function checkHandleLogout(Request $request) {
        // Récupération du paramètre
        $logoutRequest = $request->request->get('logoutRequest');
        // Les chaines recherchés
        $open = '<samlp:SessionIndex>';
        $close = '</samlp:SessionIndex>';

        // Isolation de la clé de session
        $begin = strpos($logoutRequest, $open);
        $end = strpos($logoutRequest, $close, $begin);
        $sessionID = substr($logoutRequest, $begin+strlen($open), $end-strlen($close)-$begin+1);

        // Changement de session et destruction pour forcer l'authentification CAS à la prochaine visite
        session_start();
        session_id($sessionID);
        session_destroy();
    }
}
