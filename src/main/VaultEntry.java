/**
 * Abstract class representing a generic vault entry
 * This serves as a base class for PasswordEntry and PrivateKeyEntry
 * It contains shared attributes,  service name and IV used for encryption
 */
public abstract class VaultEntry {

    protected String iv;      
    protected String service; // service name 


     /**
     * Constructs a VaultEntry with given IV and service name.
     *
     * @param iv      Base64 encoded IV used for encryption
     * @param service Name of the service associated with entry
     */
    public VaultEntry(String iv, String service) {
        this.iv = iv;
        this.service = service;
    }

    /**
     * Gets the IV used for encryption.
     *
     * @return The IV as a Base64-encoded string.
     */
    public String getIv() { return iv; }

    /**
     * Gets the service name.
     *
     * @return The service name.
     */
    public String getService() { return service; }

}
