<?php

namespace ionmvc\packages\cookie\classes;

use ionmvc\classes\config;
use ionmvc\classes\http;
use ionmvc\classes\igsr;
use ionmvc\classes\input;
use ionmvc\classes\request;
use ionmvc\exceptions\app as app_exception;

class cookie {

	const remove       = -3600;
	const session_only = 0;
	const one_hour     = 3600;
	const six_hours    = 21600;
	const one_day      = 86400;
	const one_month    = 2592000;
	const six_months   = 15552000;
	const one_year     = 31104000;

	private $config = [
		'salt'   => false,
		'prefix' => false
	];

	private $data = null;
	private $cookies = [];

	public static function __callStatic( $method,$args ) {
		$class = request::cookie();
		$method = "_{$method}";
		if ( !method_exists( $class,$method ) ) {
			throw new app_exception( "Method '%s' not found",$method );
		}
		return call_user_func_array( [ $class,$method ],$args );
	}

	public function __construct() {
		$this->config = array_merge( $this->config,config::get('cookie',[]) );
		if ( $this->config['salt'] === false ) {
			throw new app_exception('Cookie salt string must be set in config');
		}
		$data = input::cookie();
		$this->data = new igsr( $data );
		$this->data->callback( igsr::is_set,[ $this,'check_hash' ] );
		$this->data->callback( igsr::get,[ $this,'check_hash' ] );
		request::hook()->attach('destruct',function() {
			$this->handle();
		});
	}

	private function build_header( $name ) {
		$cookie = $this->cookies[$name];
		$data  = 'Set-cookie: ' . urlencode( $name ) . '=' . urlencode( sha1( $this->config['salt'] . $cookie['value'] ) . '-' . $cookie['value'] );
		if ( $cookie['expiry'] !== 0 ) {
			$data .= '; expires=' . gmdate( 'D, d-M-Y H:i:s T',$cookie['expiry'] );
		}
		if ( $cookie['path'] !== '' ) {
			$data .= "; path={$cookie['path']}";
		}
		if ( $cookie['domain'] !== false ) {
			$data .= "; domain={$cookie['domain']}";
		}
		if ( $cookie['secure'] ) {
			$data .= '; secure';
		}
		if ( $cookie['httponly'] ) {
			$data .= '; httponly';
		}
		return $data;
	}

	private function handle() {
		foreach( array_keys( $this->cookies ) as $name ) {
			http::header( $this->build_header( $name ) );
		}
	}

	public function _is_set() {
		$args = func_get_args();
		if ( $this->config['prefix'] !== false ) {
			$args = array_map( function( $value ) {
				return $this->config['prefix'] . $value;
			},$args );
		}
		return $this->data->is_set( $args );
	}

	public function _get( $name ) {
		if ( $this->config['prefix'] !== false ) {
			$name = $this->config['prefix'] . $name;
		}
		return $this->data->get( $name );
	}

	private function get_domain( $domain ) {
		if ( !is_null( $domain ) ) {
			return $domain;
		}
		$server_name = input::server('SERVER_NAME');
		if ( $server_name === 'localhost' ) {
			return false;
		}
		if ( ( $http_host = input::server('HTTP_HOST',false) ) !== false ) {
			return $http_host;
		}
		return $server_name;
	}

	public function _set( $name,$value,$expiry=self::one_day,$path='/',$domain=null,$secure=false,$httponly=false ) {
		if ( preg_match( '#^[a-zA-Z0-9_]+$#',$name ) !== 1 ) {
			throw new app_exception('Cookie name is not valid');
		}
		$expiry = ( is_numeric( $expiry ) ? time() + $expiry : strtotime( $expiry ) );
		$server_name = input::server('SERVER_NAME');
		$domain = $this->get_domain( $domain );
		$this->cookies[$name] = compact('name','value','expiry','path','domain','secure','httponly');
	}

	public function _remove( $name,$expiry=self::remove,$path='/',$domain=null,$secure=false,$httponly=false ) {
		$domain = $this->get_domain( $domain );
		$this->_set( $name,'removed',$expiry,$path,$domain,$secure,$httponly );
	}

	public function check_hash( $type,$arg,$value,$igsr ) {
		if ( $value === false ) {
			return false;
		}
		if ( $type === igsr::is_set ) {
			$value = $igsr->get( $arg );
			return ( $value !== false );
		}
		list( $hash,$value ) = explode( '-',$value,2 );
		if ( $hash !== sha1( $this->config['salt'] . $value ) ) {
			return false;
		}
		return $value;
	}

}