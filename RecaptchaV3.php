<?php
namespace Elvin;

class RecaptchaV3 {
    private string $siteKey;
    private string $secretKey;
    private string $url = 'https://www.google.com/recaptcha/api.js?render=';
        // Constants for URLs
    private const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';
    private float $threshold = 0.5;
    private array $responseObj = [];

    /**
     * Sets the site key for reCAPTCHA v3.
     *
     * @param string $key The site key to set.
     */
    public function setSiteKey(string $key): void {
        $this->siteKey = $key;
    }

    /**
     * Retrieves the site key for reCAPTCHA v3.
     *
     * @return string The site key.
     */
    public function getSiteKey(): string {
        return $this->siteKey;
    }

    /**
     * Sets the secret key for reCAPTCHA v3.
     *
     * @param string $key The secret key to set.
     */
    public function setSecretKey(string $key): void {
        $this->secretKey = $key;
    }

    /**
     * Retrieves the secret key for reCAPTCHA v3.
     *
     * @return string The secret key.
     */
    public function getSecretKey(): string {
        return $this->secretKey;
    }

    /**
     * Generates the complete URL for embedding the reCAPTCHA v3 script with the provided site key.
     *
     * @return string The complete URL for embedding reCAPTCHA v3 script.
     */
    public function getUrl(): string {
        return $this->url . $this->siteKey;
    }

    // Add error handling for cURL request failures
    private function _verifyFromServer(string $token) {
        $postArray = [
            'secret' => $this->getSecretKey(),
            'response' => $token,
        ];

        $postJSON = http_build_query($postArray);

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, self::RECAPTCHA_VERIFY_URL);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $postJSON);
        $response = curl_exec($curl);
        curl_close($curl);
        $curlResponseArray = json_decode($response, true);
        $this->responseObj = $curlResponseArray;

        return $this->responseObj;
    }

    // Add PHPDoc comments for documentation
    /**
     * Verify the reCAPTCHA token.
     *
     * @param string $token The reCAPTCHA token to verify.
     * @return array The verification response from the server.
     */
    public function verify(string $token) {
        return $this->_verifyFromServer($token);
    }

    /**
     * Check if the score meets the threshold for success.
     *
     * @return bool Whether the score meets the threshold.
     */
    public function isThresholdPassed(): bool {
        return $this->score() >= $this->threshold;
    }

    /**
     * Get the success status from the response.
     *
     * @return bool The success status.
     */
    public function success(): bool {
        return isset($this->responseObj['success']) && $this->responseObj['success'] === true;
    }

    /**
     * Get the challenge timestamp from the response.
     *
     * @return string The challenge timestamp.
     */
    public function challengeTs(): string {
        return $this->responseObj['challenge_ts'] ?? '';
    }

    /**
     * Get the hostname from the response.
     *
     * @return string The hostname.
     */
    public function hostname(): string {
        return $this->responseObj['hostname'] ?? '';
    }

    /**
     * Get the score from the response.
     *
     * @return float The score.
     */
    public function score(): float {
        return $this->responseObj['score'] ?? 0.0;
    }

    /**
     * Get the action from the response.
     *
     * @return string The action.
     */
    public function action(): string {
        return $this->responseObj['action'] ?? '';
    }
}
