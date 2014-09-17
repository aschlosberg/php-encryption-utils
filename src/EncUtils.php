<?php

namespace Oonix\Encryption;

/**
 * Convenience wrapper for openssl_[en|de]crypt()
 * 
 * @package oonix/encryption-utils
 * @author Arran Schlosberg <arran@oonix.com.au>
 * @license GPL-3.0
 */
class EncUtils {

	/**
	 * Cipher method for use with openssl_[en|de]crypt()
	 *
	 * @var string
	 * @access private
	 */
	private $_cipher;
	
	/**
	 * Should we allow the initialisation vector for the encryption to be derived from a cryptographically weak PRNG
	 *
	 * @var bool
	 * @access private
	 */
	private $_allow_weak_rand;
	
	/**
	 * Options to be passed to openssl_[en|de]crypt()
	 * OPENSSL_RAW_DATA and/or OPENSSL_ZERO_PADDING
	 * Use of OPENSSL_RAW_DATA will store cipher text and IV concatenated as raw bytes, otherwise as base 64 encoded strings
	 *
	 * @var int
	 * @access private
	 */
	private $_openssl_options;
	
	/**
	 * Symmetric encryption key
	 *
	 * @var string
	 * @access private
	 */
	private $_key;
	
	/**
	 * As PHP does not currently support GCM cipher mode, automatically include a ciphertext MAC. Set explicitly to false to disable;
	 * 
	 * @var bool
	 * @access private
	 */
	private $_hmacAlgo;
	
	/**
	 * The key to use when generating the HMAC of the ciphertext. If null, one is generated from the encryption key and a salt.
	 * 
	 * @var string
	 * @access private
	 */
	private $_hmacKey;
	
	/**
	 * Entropy for the generation of the HMAC key when one is not explicitly provided.
	 * 
	 * @var string
	 * @access private
	 */
	private $_hmacSalt;
	
	/**
	 * Some functions modify private attributes in a manner that is undesirable for multiple encrypt/decrypt operations.
	 * For example, without an explicit HMAC key, one is created and then used for the life of the object.
	 * Store the attributes in a config stack, push at the beginning of encrypt/decrypt and pop at the end
	 * 
	 * @var array
	 * @access private
	 */
	private $_configStack = array();
	
	/**
	 * Constructor
	 *
	 * Store the configuration directives. Implements checks and then stores each in the equivalent private parameter.
	 *
	 * @param string $key				See attribute $_key.
	 * @param string $cipher			See attribute $_cipher.
	 * @param int $openssl_options		See attribute $_openssl_options.
	 * @param bool $allow_weak_rand		See attribute $_allow_weak_rand.
	 * @param bool $hmacAlgo				See attribute $_hmacAlgo.
	 * @param string $hmacKey			See attribute $_hmacKey.
	 * @access public
	 */
	public function __construct($key, $cipher, $openssl_options = 0, $allow_weak_rand = false, $hmacAlgo = 'sha512', $hmacKey = null){
		if(!function_exists('openssl_encrypt')){
			throw new EncryptException("OpenSSL encryption functions required.");
		}
		
		if(!in_array($cipher, openssl_get_cipher_methods(true))){
			throw new EncryptException("The cipher '{$cipher}' is not available. Use openssl_get_cipher_methods() for a list of available methods.");
		}
		
		if($hmacAlgo!==false && !in_array($hmacAlgo, hash_algos())){
			throw new EncryptException("The hash algorithm '{$hmacAlgo}' is not available. Use hash_algos() for a list of available algorithms.");
		}

		$this->_key = $key;
		$this->_cipher = $cipher;
		$this->_allow_weak_rand = $allow_weak_rand===true;
		$this->_openssl_options = is_int($openssl_options) ? $openssl_options : 0;
		$this->_hmacAlgo = $hmacAlgo;
		$this->_hmacKey = $hmacKey;
	}
	
	/**
	 * Convenience function to check if OpenSSL options specify raw data usage; __get and __set will treat cipher text in the same manner.
	 *
	 * @access public
	 * @return bool
	 */
	public function useRaw(){
		return ($this->_openssl_options & OPENSSL_RAW_DATA) > 0;
	}
	
	/**
	 * Encrypt
	 *
	 * @param string $plain_text	Plain text data.
	 * @param bool	$as_array		Return IV and cipher text as an array rather than concatenated.
	 * @access public
	 * @return mixed
	 */
	public function encrypt($plain_text, $as_array = false){
		$this->configPush();
		$strong = false;
		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->_cipher), $strong);
		if(!$strong && $this->_allow_weak_rand!==true){
			throw new EncryptException("A cryptographically weak algorithm was used in the generation of the initialisation vector.");
		}
		$cipher_text = array(
			$iv,
			openssl_encrypt($plain_text, $this->_cipher, $this->_key, $this->_openssl_options & OPENSSL_RAW_DATA, $iv) //will base64 encode later if not raw
		);
		$prefix = 0;
		if($this->_hmacAlgo!==false){
			$prefix = 1;
			$hmac = $this->hmac($cipher_text[1]); //this MUST occur before unshifting values otherwise hmacSalt won't yet exist if it is to be generated
			array_unshift($cipher_text, $this->_hmacSalt, $hmac);
		}
		if(!$this->useRaw()){
			$this->base64($cipher_text);
		}
		$this->configPop();
		return $as_array ? $cipher_text : $prefix.implode($this->useRaw() ? null : "_", $cipher_text); //underscore is not part of MIME base64
	}
	
	/**
	 * Decrypt
	 * 
	 * @param mixed $cipher_text		Cipher_text data as array($iv, $cipher_text) or concatenated string $iv.$cipher_text
	 * @access public
	 * @return string
	 */
	public function decrypt($cipher_text){
		$this->configPush();
		$hmac = false;
		if(!is_array($cipher_text)){
			$authenticate = substr($cipher_text, 0, 1)=='1';
			$cipher_text = substr($cipher_text, 1);
			if($this->useRaw()){
				$lengths = array(openssl_cipher_iv_length($this->_cipher));
				if($authenticate){
					array_unshift($lengths, 64, strlen(hash($this->_hmacAlgo, "", true)));
				}
				$arr = array();
				foreach($lengths as $len){
					$arr[] = substr($cipher_text, 0, $len);
					$cipher_text = substr($cipher_text, $len);
				}
				$arr[] = $cipher_text;
				$cipher_text = $arr;
			}
			else {
				$cipher_text = explode("_", $cipher_text);
			}
		}
		if(!$this->useRaw()){
			$this->base64($cipher_text, false);
		}
		if(count($cipher_text)==4){
			$this->_hmacSalt = array_shift($cipher_text);
			$hmac = array_shift($cipher_text);
		}
		$iv = $cipher_text[0];
		$cipher_text = $cipher_text[1];
		if($hmac!==false){
			$check = $this->hmac($cipher_text);
			if($hmac!==$check){
				throw new EncryptException("Cipher text authentication failed.");
			}
		}
		$this->configPop();
		return openssl_decrypt($cipher_text, $this->_cipher, $this->_key, $this->_openssl_options, $iv);;
	}
	
	/**
	 * Base64 encode / decode array of strings
	 */
	public function base64(&$arr, $encode = true){
		foreach($arr as $k => $v){
			$arr[$k] = $encode ? base64_encode($v) : base64_decode($v);
		}
	}
	
	/**
	 * Get / set configuration
	 */
	public function config($key, $val = null){
		$key = "_{$key}";
		if(!isset($this->$key)){
			throw new EncryptException("Configuration directive '{$key}' does not exist.");
		}
		if(!is_null($val)){
			$this->$key = $val;
		}
		return $key;
	}
	
	/**
	 * Store a copy of the current config in a stack
	 */
	private function configPush(){
		$curr = get_object_vars($this);
		unset($curr['_configStack']);
		$this->_configStack[] = $curr;
	}
	
	/**
	 * Return config from the top of the stack, or leave as-is if empty
	 */
	private function configPop(){
		if(count($this->_configStack)){
			$reset = array_pop($this->_configStack);
			foreach($reset as $k => $v){
				$this->$k = $v;
			}
		}
	}
	
	/**
	 * Compute the HMAC of cipher text; optionally generate the HMAC key from the encryption key if it is not explicitly set.
	 */
	public function hmac($cipher_text){
		if(is_null($this->_hmacKey)){
			if(is_null($this->_hmacSalt)){
				$this->_hmacSalt = openssl_random_pseudo_bytes(64, $strong);
				if(!$strong && $this->_allow_weak_rand!==true){
					throw new EncryptException("A cryptographically weak algorithm was used in the generation of the HMAC salt.");
				}
			}
			$this->_hmacKey = hash_pbkdf2($this->_hmacAlgo, $this->_key, $this->_hmacSalt, 128, 0, true);
		}
		return hash_hmac($this->_hmacAlgo, $cipher_text, $this->_hmacKey, 1);
	}
}

?>
