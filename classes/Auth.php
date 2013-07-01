<?php
/**
 * Basic authorization module
 *
 * @method static Auth factory() factory( $configAlias = 'default' )
 */
class Auth extends \Erum\ModuleAbstract
{
    /**
     * Auth model DAO
     *
     * @var string
     */
    private $dao;

    /**
     * Salt for encryption
     *
     * @var string
     */
    private $salt;

    /**
     * Cookie name for storing auth token
     *
     * @var string
     */
    private $cookie;
    
    public function __construct( array $config )
    {
        $this->dao = $config[ 'dao' ];
        
        $this->salt = isset( $config[ 'salt' ] ) ? $config['salt'] : null;
    }

    public function request( $login, $password )
    {
        $dao = $this->dao;

        return $dao::authRequest( $login, $password );
    }

    public function store( $authId, $timeout = 0 )
    {
        $dao        = $this->dao;
        $authToken  = $this->generateToken();

        if( !$dao::authSet( $authToken, $authId, $timeout ) )
        {
            $authToken = false;
        }

        return $authToken;
    }

    public function get( $token )
    {
        $dao    = $this->dao;
        $authId = false;

        // if token was compromised - kill it
        if( !$this->validateToken( $token ) )
        {
            $this->destroy( $token );
        }
        else
        {
            $authId = $dao::authGet( $token );
        }

        return $authId;
    }

    public function destroy( $token )
    {
        $dao = $this->dao;

        return $dao::authDestroy( $token );
    }

    public function validateToken( $token )
    {
        return strpos( $token, $this->getSignature() ) === 0;
    }

    private function generateToken()
    {
        return $this->getSignature() . sha1( microtime( true ) . rand( 0, time() ) );
    }

    private function getSignature()
    {
        $hash = $this->salt;

        return md5( $hash );
    }
}
