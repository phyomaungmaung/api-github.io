<?php
class AES
{
    protected $cipher;
    protected $mode;
    protected $pad_method;
    protected $secret_key;
    protected $iv;
 
    public function __construct($key, $method = 'pkcs7', $iv = '', $mode = MCRYPT_MODE_ECB, $cipher = MCRYPT_RIJNDAEL_128)
    {
        $this->secret_key = $key;
        $this->pad_method =$method;
        $this->iv = $iv;
        $this->mode = $mode;
        $this->cipher = $cipher;
    }
 
    protected function pad_or_unpad($str, $ext)
    {
        if (!is_null($this->pad_method)) {
            $func_name = __CLASS__ . '::' . $this->pad_method . '_' . $ext . 'pad';
            if (is_callable($func_name)) {
                $size = mcrypt_get_block_size($this->cipher, $this->mode);
                return call_user_func($func_name, $str, $size);
            }
        }
        return $str;
    }
 
    protected function pad($str)
    {
        return $this->pad_or_unpad($str, '');
    }
 
    protected function unpad($str)
    {
        return $this->pad_or_unpad($str, 'un');
    }
 
    public function encrypt($str)
    {
        $str = $this->pad($str);
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');
        if (empty($this->iv)) {
            $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        } else {
            $iv = $this->iv;
        }
        
        mcrypt_generic_init($td, $this->secret_key, $iv);
        $cyper_text = mcrypt_generic($td, $str);
        $rt = base64_encode($cyper_text);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        return $rt;
    }
/*
    public function decrypt($str)
    {
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');
        if (empty($this->iv)) {
            $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        } else {
            $iv = $this->iv;
        }
        
        mcrypt_generic_init($td, $this->secret_key, $iv);
        $decrypted_text = mdecrypt_generic($td, base64_decode($str));
        $rt = $decrypted_text;
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        return $this->unpad($rt);
    }
*/
	function decrypt($ciphertext) {
		$chiperRaw = base64_decode($ciphertext);
		$originalData = openssl_decrypt($chiperRaw, 'AES-256-ECB', $this->secret_key, OPENSSL_RAW_DATA);
		return $originalData;
	}
 
    public static function pkcs7_pad($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }
 
    public static function pkcs7_unpad($text)
    {
        $pad = ord($text[strlen($text) - 1]);
        if ($pad > strlen($text)) return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;
        return substr($text, 0, -1 * $pad);
    }
}

$aes = new AES('n6atpjz75hw213yfldg80ocreb9vukiq'); //key //‘transactionid|amount|companyId|paymenttype’

$test_param = [
	'paymenttype' => 'MPU',
	'encryptedString' => $aes->encrypt('0MPUMTG51|1000|10002032|MPU'),
	'amount' => '1000',
	'companyId' => '10002032',
	'transactionid' => '0MPUMTG51',
	'phoneNo' => '',
	'serviceData' => 'Payment',
	'sandbox' => 'ON',
	
];

$url = 'http://paymentuat.mmpaymal.com/payment/paymentapi';
$result = json_decode(httpPost($url, $test_param, 'json'));
$decrypted_value = $aes->decrypt($result->encryptedString);
$mpu = json_decode($decrypted_value);
$mpu_url = [
	'currencyCode' => $mpu->currencyCode,
	'merchantID' => $mpu->merchant,
	'invoiceNo' => $mpu->invoiceNo,
	'productDesc' => $mpu->productDesc,
	'userDefined1' => $mpu->userDefined1,
	'userDefined2' => $mpu->userDefined2,
	'userDefined3' => $mpu->userDefined3,
	'amount' => $mpu->amount,
	'hashValue' => $mpu->hashValue,
];

$mpu_form = httpPost($mpu->url, $mpu_url);
var_dump($mpu_form);

function httpPost($url, $data, $ext = null){
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_POST, true);
	if($ext == 'json') {
		curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
		curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
	} else {
		curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($data));
		var_dump(http_build_query($data));
	}
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($curl);
    curl_close($curl);
    return $response;
}