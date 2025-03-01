
/**
 * VaultKey is an object that holds the encrypted pair (key, IV) that are used to encrypt/decrypt vault data
 */
public class VaultKey {
    private String iv;
    private String encryptedKey;

    /**
     * Constructor for VaultKey
     * @param iv - IV used for encryption of the raw vault key
     * @param encryptedKey - encrypted version of raw vault key
     */
    public VaultKey(String iv, String encryptedKey) {
        this.iv = iv;
        this.encryptedKey = encryptedKey;
    }

    /**
     * Gets IV used for encryption of the raw vault key
     * @return - IV in Base64 format
     */
    public String getIv() {
        return iv;
    }


    /**
     * Gets encrypted vault key
     * @return - encrypted vault key in Base64 format
     */
    public String getEncryptedKey() {
        return encryptedKey;
    }
    
}
