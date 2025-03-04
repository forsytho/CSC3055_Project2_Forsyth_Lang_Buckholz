/**
 * Represents a stored password entry in the vault
 * This class extends VaultEntry and includes encrypted password
 */
public class PasswordEntry extends VaultEntry {
    private String pass; // Encrypted password
    private String user; // Username for the service

    /**
     * Constructs a PasswordEntry with the given IV, service name, and password
     *
     * @param iv      Base64-encoded IV used for encryption
     * @param service name of the service associated with the password
     * @param user    username for the service
     * @param pass    encrypted password stored as a Base64-encoded string
     */
    public PasswordEntry(String iv, String service, String user, String pass) {
        super(iv, service);
        this.user = user;
        this.pass = pass;
    }


    /**
     * Gets username 
     * @return user
     */
    public String getUser() { return user; }

    /**
     * Gets the password
     *
     * @return encrypted password as a Base64 string
     */
    public String getPass() { return pass; }

}
