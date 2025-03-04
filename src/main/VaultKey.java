
/**
 * VaultKey is an object that holds the encrypted pair (key, IV) 
 */
public class VaultKey {
    private String iv;
    private String key;

    /**
     * Constructor for VaultKey
     * @param iv - IV used for encryption of the raw vault key
     * @param Key - encrypted version of raw vault key
     */
    public VaultKey(String iv, String key) {
        this.iv = iv;
        this.key = key;
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
    public String getKey() {
        return key;
    }
    
}
