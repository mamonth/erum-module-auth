<?php
class Auth extends \Erum\ModuleAbstract
{

    /**
     * Current authorized model
     *
     * @var \Erum\ModelAbstract
     */
    private $model;

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
    
    public function __construct( array $config )
    {
        $this->dao = $config[ 'dao' ];
        
        $this->salt = isset( $config[ 'salt' ] ) ? $config['salt'] : null;
    }
    
    /**
     * Enter description here...
     *
     * @return  \Erum\ModelAbstract
     */
    public function current()
    {
        
        $dao = $this->dao;
        
        $modelClass = $dao::getModelClass();
        
        if ( null === $this->model && \Erum\Session::current()->authId )
        {
            $model = $dao::get( explode( chr(1), \Erum\Session::current()->authId ) );
            
            if( $model instanceof $modelClass  )
            {
                $this->model = $model;
            }
            else //something goes wrong
            {
                \Erum\Session::current()->authId = null;
            }
        }
        
        return $this->model;
    }

    public function request( $login, $password, $remember = false )
    {
        $dao = $this->dao;
        $modelClass = $dao::getModelClass();
        
        $model = $dao::authRequest( $login, $password );
        
        if( $model instanceof $modelClass )
        {
            $this->model = $model;

            $identityProperty = (array)$this->model->identityProperty();

            $key = array();

            while( list( ,$property ) = each( $identityProperty ) )
            {
                $key[] = $this->model->{$property};
            }

            \Erum\Session::current()->set( 'authId', implode( chr(1), $key ) );
            
            return true;
        }
        
        return false;
    }

    public function destroy()
    {
        \Erum\Session::current()->authId = null;
    }

}
