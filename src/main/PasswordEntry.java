/**
 * Represents a stored password entry in the vault
 * This class extends VaultEntry and includes encrypted password
 */
public class PasswordEntry extends VaultEntry {
    private String pass; // Encrypted password

    public PasswordEntry(String iv, String service, String pass) {
        super(iv, service);
        this.pass = pass;
    }

    public String getPass() { return pass; }

}
