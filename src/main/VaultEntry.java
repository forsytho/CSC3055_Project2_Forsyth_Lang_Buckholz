/**
 * Abstract class representing a generic vault entry
 * This serves as a base class for PasswordEntry and PrivateKeyEntry
 * It contains shared attributes,  service name and IV used for encryption
 */
public abstract class VaultEntry {

    protected String iv;
    protected String service;

    // Default constructor for Jackson
    public VaultEntry() {
    }

    // Constructor
    public VaultEntry(String iv, String service) {
        this.iv = iv;
        this.service = service; 
    }

    // Getters and setters
    
    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }
}
