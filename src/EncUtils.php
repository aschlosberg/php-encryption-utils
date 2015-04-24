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
	 * Input keying material for HKDF. Is the value provided as $key, and $_key is instead derived using HKDF.
	 *
	 * @var string
	 * @access private
	 */
	private $_ikm;
	
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
	 * @param string $hmacAlgo				See attribute $_hmacAlgo.
	 * @param mixed $hmacKey			See attribute $_hmacKey. Ignored if $useHKDF is true.
	 * @param bool $useHKDF         Use HKDF to derive both the encryption key and the HMAC key, using $_key as the IKM. Will overwrite $_key and $_hmacKey.
	 * @access public
	 */
	public function __construct($key, $cipher, $openssl_options = 0, $allow_weak_rand = false, $hmacAlgo = 'sha512', $hmacKey = null, $useHKDF = false){
		if(!function_exists('openssl_encrypt')){
			throw new EncryptException("OpenSSL encryption functions required.");
		}
		
		if(!in_array($cipher, openssl_get_cipher_methods(true))){
			throw new EncryptException("The cipher '{$cipher}' is not available. Use openssl_get_cipher_methods() for a list of available methods.");
		}
		
		if($hmacAlgo!==false && !in_array($hmacAlgo, hash_algos())){
			throw new EncryptException("The hash algorithm '{$hmacAlgo}' is not available. Use hash_algos() for a list of available algorithms.");
		}

		if($useHKDF && $hmacAlgo!==false){
		   $this->_ikm = $key;
		   $this->_key = self::hkdf($key, 256, 'Encryption', $this->hmacSalt(), $hmacAlgo);
		   $this->_hmacKey = self::hkdf($key, 256, 'HMAC', $this->hmacSalt(), $hmacAlgo);
		}
		else {
		   $this->_key = $key;
		   $this->_hmacKey = $hmacKey;
		}
		$this->_cipher = $cipher;
		$this->_allow_weak_rand = $allow_weak_rand===true;
		$this->_openssl_options = is_int($openssl_options) ? $openssl_options : 0;
		$this->_hmacAlgo = $hmacAlgo;
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
			if((function_exists('hash_equals') && !hash_equals($check, $hmac)) || $check!=$hmac){ //timing-attack mitigation if available
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
		if(is_null($this->_hmacKey)){ //if $useHKDF was stipulated in construction then this will never be the case; this deprecated PBKDF2 method was before I knew of HKDF, but remains for backward compatibility
			$this->_hmacKey = hash_pbkdf2($this->_hmacAlgo, $this->_key, $this->hmacSalt(), 128, 0, true);
		}
		return hash_hmac($this->_hmacAlgo, $cipher_text, $this->_hmacKey, 1);
	}
	
	/**
	 * Return a salt for use with either:
	 * (a) Generation of an HMAC key if not using HKDF, or
	 * (b) Use in HKDF
	 * 
	 * Generate if not already existing.
	 */
	public function hmacSalt(){
	   if(is_null($this->_hmacSalt)){
	      $this->_hmacSalt = openssl_random_pseudo_bytes(64, $strong);
	      if(!$strong && $this->_allow_weak_rand!==true){
	         throw new EncryptException("A cryptographically weak algorithm was used in the generation of the HMAC salt.");
	      }
	   }
	   return $this->_hmacSalt;
	}
	
	/**
	 *  Implement PRK as defined in RFC 5869. Separate it from the HKDF function as the test vectors include the PRK value.
	 *  
	 *  @param string $IKM   A source of entropy (Input Keying Material)
	 *  @param string $salt  Although salt is optional in HKDF because it has a default value, the PRK utilises this value so has no default here.
	 *  @param string $hash  Algorithm for use in HMAC
	 *  @return string       Binary string
	 */
	public static function PRK($IKM, $salt, $hash){
      return hash_hmac($hash, $IKM, $salt, true);
   }
   
   /**
    * Implement HKDF as defined in RFC 5869.
    * 
    * @param string $IKM   A source of entropy (Input Keying Material)
    * @param int $L    Length of output. Although RFC does not include a default value, this implementation defaults to the output size of the hash algorithm.
    * @param string $info  Context info for the key generation.
    * @param string $salt  Optional as its default value is stipulated in the RFC
    * @param string $hash  Algorithm for use in HMAC
    * @return string       Binary string
    */
   public static function hkdf($IKM, $L=null, $info=null, $salt=null, $hash='sha256'){
      $HashLen = strlen(hash_hmac($hash, null, null)) / 2;
      $L = $L ?: $HashLen;
      if($L > 255*$HashLen){
         return null;
      }
       
      //test vectors pass when leaving salt as null; could exclude this line, but then it's dependent on some inner PHP workings that may change
      $salt = $salt ?: str_repeat("\0", $HashLen);
       
      $PRK = self::PRK($IKM, $salt, $hash);
       
      $N = ceil($L / $HashLen);
      $T = [null];
       
      for($i=1; $i<=$N; $i++){
         $iterator = hex2bin(str_pad($i, 2, "0", STR_PAD_LEFT));
         $T[$i] = hash_hmac($hash, $T[$i-1].$info.$iterator, $PRK, true);
      }
       
      return substr(implode(null, $T), 0, $L);
   }
}

?>
