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
	private $_allow_weak_iv;
	
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
	 * Constructor
	 *
	 * Store the configuration directives. Implements checks and then stores each in the equivalent private parameter.
	 *
	 * @param string $key				See attribute $_key.
	 * @param string $cipher			See attribute $_cipher.
	 * @param int $openssl_options	See attribute $_openssl_options.
	 * @param bool $allow_weak_iv		See attribute $_allow_weak_iv.
	 * @access public
	 */
	public function __construct($key, $cipher, $openssl_options = 0, $allow_weak_iv = false){
		if(!function_exists('openssl_encrypt')){
			throw new EncryptException("OpenSSL encryption functions required.");
		}
		
		if(!in_array($cipher, openssl_get_cipher_methods(true))){
			throw new EncryptException("The cipher '{$cipher}' is not available. Use openssl_get_cipher_methods() for a list of available methods.");
		}

		$this->_key = $key;
		$this->_cipher = $cipher;
		$this->_allow_weak_iv = $allow_weak_iv===true;
		$this->_openssl_options = is_int($openssl_options) ? $openssl_options : 0;
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
		$strong = false;
		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->_cipher), $strong);
		if(!$strong && $this->_allow_weak_iv!==true){
			throw new EncryptException("A cryptographically weak algorithm was used in the generation of the initialisation vector.");
		}
		$cipher_text = array(
			$this->useRaw() ? $iv : base64_encode($iv),
			openssl_encrypt($plain_text, $this->_cipher, $this->_key, $this->_openssl_options, $iv)
		);
		return $as_array ? $cipher_text : implode("", $cipher_text);
	}
	
	/**
	 * Decrypt
	 * 
	 * @param mixed $cipher_text		Cipher_text data as array($iv, $cipher_text) or concatenated string $iv.$cipher_text
	 * @access public
	 * @return string
	 */
	public function decrypt($cipher_text){
		if(is_array($cipher_text)){
			$iv = $cipher_text[0];
			$cipher_text = $cipher_text[1];
		}
		else {
			$len = openssl_cipher_iv_length($this->_cipher);
			if($this->useRaw()){
				$iv = substr($cipher_text, 0, $len);
				$cipher_text = substr($cipher_text, $len);
			}
			else {
				/**
				 * The number of = used to pad base 64 strings is dependent on the number of bytes in the final 2-byte grouping; = for even and == for odd
				 */
				$iv_pad = ($len % 2) ? "=" : "==";
				list($iv, $cipher_text) = explode($iv_pad, $cipher_text, 2);
				$iv = base64_decode("{$iv}{$iv_pad}");
			}
		}
		return openssl_decrypt($cipher_text, $this->_cipher, $this->_key, $this->_openssl_options, $iv);
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
}

?>
