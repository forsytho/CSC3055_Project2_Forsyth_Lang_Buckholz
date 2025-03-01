/**
 * Abstract class representing a generic vault entry
 * This serves as a base class for PasswordEntry and PrivateKeyEntry
 * It contains shared attributes,  service name and IV used for encryption
 */
public abstract class VaultEntry {

    protected String iv;      
    protected String service; // service name 

    public VaultEntry(String iv, String service) {
        this.iv = iv;
        this.service = service;
    }

    public String getIv() { return iv; }
    public String getService() { return service; }

}
