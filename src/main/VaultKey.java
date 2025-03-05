
/**
 * VaultKey is an object that holds the encrypted pair (key, IV) 
 */
public class VaultKey {
    private String iv;
    private String key;


    // Default constructor for Jackson JSON serialization
    public VaultKey() {
    }

    // Constructor
    public VaultKey(String iv, String key) {
        this.iv = iv;
        this.key = key;
    }

   // getters and setters

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

   
    public String getKey() {
        return key;
    }
    
    public void setKey(String key) {
        this.key = key;
    }
}
