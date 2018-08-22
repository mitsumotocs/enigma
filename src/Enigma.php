<?php
class Enigma
{
    const DEFAULT_CIPHER = 'AES-128-CBC';
    const DEFAULT_HASH = 'sha256';

    protected $cipher;
    protected $hash;

    /**
     * Enigma constructor.
     * @param string|null $cipher
     * @param string|null $hash
     */
    public function __construct($cipher = null, $hash = null)
    {
        if (isset($cipher)) {
            if (in_array($cipher, openssl_get_cipher_methods(), true)) {
                $this->cipher = $cipher;
            } else {
                throw new \InvalidArgumentException('Invalid or unsupported cipher method.');
            }
        } else {
            $this->cipher = static::DEFAULT_CIPHER;
        }

        if (isset($hash)) {
            if (in_array($hash, hash_algos(), true)) {
                $this->hash = $hash;
            } else {
                throw new \InvalidArgumentException('Invalid or unsupported hash method.');
            }
        } else {
            $this->hash = static::DEFAULT_HASH;
        }
    }

    /**
     * @param mixed $data
     * @return string
     */
    protected function hash($data)
    {
        return hash($this->hash, $data);
    }

    /**
     * @return int
     */
    protected function getIvLength()
    {
        return openssl_cipher_iv_length($this->cipher);
    }

    /**
     * @param mixed $data
     * @param string $key
     * @return string
     */
    public function encrypt($data, $key)
    {
        $iv = openssl_random_pseudo_bytes($this->getIvLength());
        $encrypted = openssl_encrypt($data, $this->cipher, $this->hash($key), OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * @param mixed $data
     * @param string $key
     * @return string
     */
    public function decrypt($data, $key)
    {
        $data = base64_decode($data);
        $iv = substr($data, 0, $this->getIvLength());
        $encrypted = substr($data, $this->getIvLength());
        $decrypted = openssl_decrypt($encrypted, $this->cipher, $this->hash($key), OPENSSL_RAW_DATA, $iv);
        return $decrypted;
    }
}