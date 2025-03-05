/**
 * Represents a stored password entry in the vault
 * This class extends VaultEntry and includes encrypted password
 */
public class PasswordEntry extends VaultEntry {
    private String pass; // Encrypted password
    private String user; // Username for the service

    
    // Default constructor for Jackson JSON serialization
    public PasswordEntry() {
    }

    public PasswordEntry(String iv, String service, String user, String pass) {
        super(iv, service);
        this.user = user;
        this.pass = pass;
    }



    public String getUser() { return user; }

    public String getPass() { return pass; }

    public void setUser(String user) { this.user = user; }

    public void setPass(String pass) { this.pass = pass; }

}
