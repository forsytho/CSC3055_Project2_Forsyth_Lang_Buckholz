import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Scanner;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.generators.SCrypt;
import java.io.Console;

/**
 * Represents a vault that stores encrypted passwords and private keys
 */
public class Vault {

    // Scrypt parameters
    private static final String VAULT_FILE = "vault.json";
    private static final int SCRYPT_COST = 2048;
    private static final int SCRYPT_BLOCK_SIZE = 8;
    private static final int SCRYPT_PARALLELIZATION = 1;
    private static final int SCRYPT_KEY_LENGTH = 32; // AES-256

    private VaultData vaultData; // Vault data, stored in JSON format
    private byte[] rawVaultKey; // Raw vault key, used to encrypt/decrypt secret vault data


    /**
     * Constructor for Vault class
     * 
     * If vault does not exist, creates a new vault with given password.
     * Else, attempts to load existing vault with key derived from given password
     * 
     * @param password
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public Vault(String password) throws GeneralSecurityException, IOException {
        if (!new File(VAULT_FILE).exists()) {
            createNewVault(password);
        } else {
            loadExistingVault(password);
        }
    }


    /**
     * Creates a new vault, given a password.
     * Derives vault master key with scrypt, with password and random salt
     * Randomly generates 32 byte vault encryption key, and 12 byte IV  
     * 
     * 
     * @param vaultPassword - passed in at creation to generate vault keys. User must know this password to access vault in the future
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private void createNewVault(String vaultPassword) throws GeneralSecurityException, IOException {

        System.out.println("Creating a new vault...");

        // Generate salt for scrypt key derivation
        byte[] passwordSalt = CryptoUtils.generateRandomBytes(16);
        String encodedPasswordSalt = Base64.getEncoder().encodeToString(passwordSalt);

        // Derive master key from vault password + salt
        byte[] derivedMasterKey = deriveKey(vaultPassword, passwordSalt);

        // Randomly generate the raw vault encryption key (used for secrets)
        rawVaultKey = CryptoUtils.generateRandomBytes(32);

        // Randomly generate an IV that will be used for encryption of the above raw key
        byte[] vaultKeyEncryptionIV = CryptoUtils.generateRandomBytes(12);

        // Now, encrypt the raw vault key with AESGCM using: derived master key + IV
        String encryptedVaultKey = CryptoUtils.encryptAESGCM(rawVaultKey, derivedMasterKey, vaultKeyEncryptionIV);

        // Create VaultKey object (stores the encrypted vault key and associated IV)
        VaultKey vaultKeyObject = new VaultKey(
            Base64.getEncoder().encodeToString(vaultKeyEncryptionIV), 
            encryptedVaultKey
        );

        // Initialize vault data, first storing salt, and vault key object (encrypted key + IV)
        vaultData = new VaultData(encodedPasswordSalt, vaultKeyObject);

        // Save the vault to disk
        saveVault();
        System.out.println("Vault successfully created.");

    }

    private void loadExistingVault(String password) throws GeneralSecurityException, IOException {
        
        // cleared for refactoring. Must be completed

    }








    private byte[] deriveKey(String password, byte[] salt) {
        if(password == null || salt == null){
            throw new IllegalArgumentException("Error: Password and salt cannot be null.");
        }

        return SCrypt.generate(password.getBytes(StandardCharsets.UTF_8), salt, SCRYPT_COST, SCRYPT_BLOCK_SIZE, SCRYPT_PARALLELIZATION, SCRYPT_KEY_LENGTH);
    }







    public void addPasswordEntry(String service, String user, String password) throws GeneralSecurityException, IOException {

        byte[] iv = CryptoUtils.generateRandomBytes(12);
        String encryptedPassword = CryptoUtils.encryptAESGCM(password.getBytes(StandardCharsets.UTF_8), vaultKey, iv);
        vaultData.getPasswords().add(new PasswordEntry(Base64.getEncoder().encodeToString(iv), service, user, encryptedPassword));

        saveVault();
        System.out.println("Password entry added.");
    }






    /**
     * Lookup a decrypted password for a given service
     * 
     * @param service
     * @returns decrypted password for given service
     * @throws GeneralSecurityException
     */
    public String lookupPassword(String service) throws GeneralSecurityException {
        for (PasswordEntry entry : vaultData.getPasswords()) {
            if (entry.getService().equals(service)) {
                byte[] iv = Base64.getDecoder().decode(entry.getIv());
                byte[] encryptedPass = Base64.getDecoder().decode(entry.getPass());

                byte[] decryptedPass = CryptoUtils.decryptAESGCM(encryptedPass, vaultKey, iv);
                return new String(decryptedPass, StandardCharsets.UTF_8);
            }
        }
        return "Service not found.";
    }








    /**
     * Saves the vault data to a file
     * 
     * @throws IOException
     */
    private void saveVault(vaultData) throws IOException {


        File file = new File(VAULT_FILE);

        //Ensure file exists
        if(!file.exists()){
            file.createNewFile();
        }

        //Ensure vaultData is not null
        if(vaultData == null){
            System.err.println("Error: Vault data is null. Cannot save.");
            return;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(file, vaultData);
    }





    /**
     * Main method for the Vault program
     * Queries user for vault password
     * 
     * @param args
     */
    public static void main(String[] args) {


        Scanner scanner = new Scanner(System.in);
        Console console = System.console();

        String password;

        if(console != null){

            //Secure password input (hides characters)
            password = new String(console.readPassword("Vault Password: "));


        } else {


            //Fallback for IDEs
            System.out.print("Vault Password: ");
            password = scanner.nextLine();


            // must be completed


        }
    }
}
