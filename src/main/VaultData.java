import java.util.ArrayList;
import java.util.List;

/**
 * Represents the in-memory storage for the Vault
 * When the user opens the vault, data from vault.json is loaded into this object
 * When the user seals the vault, the data is copied from this object to vault.json
 * Then, this object is cleared
 */
public class VaultData {

    private String salt; // Base64-encoded salt for key derivation
    private VaultKey vaultKey; // The key object, containing base64-encoded IV and encrypted key

    // Initialize empty lists for password and private key entries, ensure they are never null
    private List<PasswordEntry> passwords = new ArrayList<>();
    private List<PrivateKeyEntry> privkeys = new ArrayList<>();

    // Default constructor for Jackson JSON serialization
    public VaultData() {
    }


    // Constructor
    public VaultData(String salt, VaultKey vaultKey) {

        this.salt = salt;
        this.vaultKey = vaultKey;
    }

    public String getSalt() { return salt; }

    public VaultKey getVaultKey() { return vaultKey; }

    public List<PasswordEntry> getPasswords() { return passwords; }
    public List<PrivateKeyEntry> getPrivkeys() { return privkeys; }

    // Optionally, setters for Jackson if needed:
    public void setSalt(String salt) { this.salt = salt; }
    public void setVaultKey(VaultKey vaultKey) { this.vaultKey = vaultKey; }
    public void setPasswords(List<PasswordEntry> passwords) { this.passwords = (passwords == null) ? new ArrayList<>() : passwords; }
    public void setPrivkeys(List<PrivateKeyEntry> privkeys) { this.privkeys = (privkeys == null) ? new ArrayList<>() : privkeys; }
    
}
