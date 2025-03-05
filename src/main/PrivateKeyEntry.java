/**
 * Represents a stored private key entry in the vault
 * This class extends VaultEntry and includes encrypted private key
 */
public class PrivateKeyEntry extends VaultEntry {

    private String privkey; // encryted private key stored as a Base64-encoded string


    // Default constructor for Jackson JSON serialization
    public PrivateKeyEntry() {
    }

    // Constructor
    public PrivateKeyEntry(String iv, String service, String privkey) {
        super(iv, service);
        this.privkey = privkey;
    }

   
    public String getPrivkey() { return privkey; }

    public void setPrivkey(String privkey) { this.privkey = privkey; }
}
