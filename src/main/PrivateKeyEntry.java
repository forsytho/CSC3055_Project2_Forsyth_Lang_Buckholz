/**
 * Represents a stored private key entry in the vault
 * This class extends VaultEntry and includes encrypted private key
 */
public class PrivateKeyEntry extends VaultEntry {

    private String privkey; // private key

    /**
     * Constructs a PrivateKeyEntry with the given IV, service name, and private key
     *
     * @param iv       Base64-encoded IV used for encryption.
     * @param service  name of the service associated with the private key.
     * @param privkey  encrypted private key stored as a Base64-encoded string.
     */
    public PrivateKeyEntry(String iv, String service, String privkey) {
        super(iv, service);
        this.privkey = privkey;
    }

    /**
     * Gets the private key
     *
     * @return encrypted private key as a Base64 string
     */
    public String getPrivkey() { return privkey; }

    /**
     * Returns a string representation of the PrivateKeyEntry
     *
     * @return A formatted string containing service name and entry type.
     */
    @Override
    public String toString() {
        return super.toString() + " | Type: PrivateKeyEntry";
    }
}
