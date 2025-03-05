import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Scanner;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.generators.SCrypt;
import java.io.Console;
import java.security.SecureRandom;

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


    // Instance variables
    private VaultData vaultData; // Vault data object, which includes base64 encoded salt, vault key, and encrypted secrets
    private byte[] rawVaultKey;  // Raw vault key, used to encrypt/decrypt secret vault data


    /**
     * Constructor for Vault class
     * 
     * If vault.json does not exist, creates a new vault with new key derived from given password.
     * Else, attempts to load existing vault with key derived from given password
     * 
     * @param password
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public Vault(String password) throws GeneralSecurityException, IOException {

        if (!new File(VAULT_FILE).exists()) {

            System.out.println("No existing vault found. ");
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
     * @param vaultPassword - passed in at creation to generate vault derived key. User must know this password to access vault in the future
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private void createNewVault(String vaultPassword) throws GeneralSecurityException, IOException {

        System.out.println("Creating a new vault...");

        // Generate salt for scrypt key derivation
        byte[] passwordSalt = CryptoUtils.generateRandomBytes(16);
        String encodedPasswordSalt = Base64.getEncoder().encodeToString(passwordSalt);

        // SCrypt: Derive master key from vault password and salt
        byte[] derivedMasterKey = deriveKey(vaultPassword, passwordSalt);

        // Randomly generate a raw vault encryption key (used for our secrets)
        rawVaultKey = CryptoUtils.generateRandomBytes(32);

        // Randomly generate an IV that will be used for AESGCM encryption of the above raw key
        byte[] vaultKeyEncryptionIV = CryptoUtils.generateRandomBytes(12);

        // Now, try to encrypt the raw vault key with AESGCM using: derived master key + IV
        String encryptedVaultKey;

        try {
            encryptedVaultKey = CryptoUtils.encryptAESGCM(rawVaultKey, derivedMasterKey, vaultKeyEncryptionIV);

        } catch (Exception e) {

            throw new GeneralSecurityException("Error encrypting vault key", e);
        }


        // Create VaultKey object (represents the encrypted vault key and associated IV)
        VaultKey vaultKeyObject = new VaultKey(
            Base64.getEncoder().encodeToString(vaultKeyEncryptionIV), 
            encryptedVaultKey
        );

        // Initialize vault data, first storing salt, and vault key object (encrypted key + IV)
        vaultData = new VaultData(encodedPasswordSalt, vaultKeyObject);

        // Immediately write the new vault to vault.json, ensures that the vault is saved even if crash happens
        JsonHandler.saveVault(vaultData);

        System.out.println("Vault successfully created.");

    }


    /**
     * Attempts to load existing vault from file, given a password 
     * If the given password does not match the vaults initial password, the vault remains locked
     * 
     * @param password
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private void loadExistingVault(String userPassword) throws GeneralSecurityException, IOException {

        System.out.println("Grabbing existing vault metadata...");

        VaultData tempVaultData = JsonHandler.loadVaultMetadata();

        if (tempVaultData == null) {
            System.err.println(" New message: temp data is null");
        }

        // check for missing crucial data
        if( tempVaultData.getSalt()               == null || 
             tempVaultData.getVaultKey().getIv()  == null || 
             tempVaultData.getVaultKey().getKey() == null  
            ) {
    
            throw new GeneralSecurityException("Error unsealing vault: missing crucial data");
        }

    
       
        // Extract salt from vault metadata
        byte[] storedSalt = Base64.getDecoder().decode(tempVaultData.getSalt());
    
        // Now, derive a potential root key using the given password and the stored salt
        byte[] derivedRootKey = deriveKey(userPassword, storedSalt);
    
        // Retrieve encrypted vault key + IV from the VaultKey object, to be decrypted with the derived root key
        byte[] vaultKeyIV = Base64.getDecoder().decode(tempVaultData.getVaultKey().getIv());
        byte[] encryptedVaultKey = Base64.getDecoder().decode(tempVaultData.getVaultKey().getKey());
    

        // Now, try decrypting the vault key using the derived root key
        try {
            
            // Recover the raw, unencrypted vault key that we use for encryption/decryption of secrets
            rawVaultKey = CryptoUtils.decryptAESGCM(encryptedVaultKey, derivedRootKey, vaultKeyIV);
    
            // If no error happened above, we have the correct password and the vault's secrets can be accessed
            vaultData = JsonHandler.loadVault();

            System.out.println("Vault successfully unsealed.");

        } catch (Exception e) {

            // If decryption fails, password is incorrect
            throw new GeneralSecurityException("Error unsealing vault: incorrect password", e);
        }
    }
    


    /**
     * Derive a key from a given password and salt using the SCrypt key derivation function
     * 
     * @param password - textual password to derive a key from
     * @param salt - salt to use in the key derivation
     * @return - derived key
     */
    private byte[] deriveKey(String password, byte[] salt) {

        if(password == null || salt == null){

            throw new IllegalArgumentException("Error: Password and salt cannot be null.");
        }
        return SCrypt.generate(password.getBytes(StandardCharsets.UTF_8), salt, SCRYPT_COST, SCRYPT_BLOCK_SIZE, SCRYPT_PARALLELIZATION, SCRYPT_KEY_LENGTH);
    }


     /**
      * Generates random password of given length for a given (service, username) pair and stores it in the vault as password entry
      * New random password is encrypted using AES-GCM with Additional Authenticated Data constructed from service and username
      *  
      * @param length   - given length of the password
      * @param service  - given service, aad
      * @param username - given username, aad

      * @throws GeneralSecurityException
      * @throws IOException
      */
    
    public void addRandomPasswordEntry(int length, String service, String username) throws GeneralSecurityException, IOException {
        
        // Generate a new random password string for the service and username
        String generatedPassword = generateRandomPassword(length);
        byte [] passwordBytes = generatedPassword.getBytes(StandardCharsets.UTF_8);

        // Generate a new IV for this password entry
        byte[] entryIV = CryptoUtils.generateRandomBytes(12);

        // Construct the additional authenticated data (AAD) for the encryption
        String aadString = service + ":" + username;
        byte[] aad = aadString.getBytes(StandardCharsets.UTF_8);

        // Encrypt the plaintext password using the raw vault key and the newly generated IV
        try {
            generatedPassword = CryptoUtils.encryptAESGCMWithAAD(
                    passwordBytes,
                    rawVaultKey,
                    entryIV,
                    aad
            );
        } catch (Exception e) {

            throw new GeneralSecurityException("Error encrypting password entry", e);
        }

        // Create a new PasswordEntry object and add it to the vault data
        PasswordEntry newEntry = new PasswordEntry(
                Base64.getEncoder().encodeToString(entryIV),
                service,
                username,
                generatedPassword
        );

        // Add the new entry to the vault data and save the updated vault to disk.
        vaultData.getPasswords().add(newEntry);

        JsonHandler.saveVault(vaultData);
    }

    //PASSWORD GENERATOR
    private String generateRandomPassword(int len) {
        //MEMBER VARIABLES
        String password;
        SecureRandom r = new SecureRandom();
        char[] letters = {'#', '$', '%', '!', '&', '*', '@', '?', 
                            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                            'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
                            'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                            't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', 
                            '3', '4', '5', '6', '7', '8', '9', '0'};
        int[] arr;

        if (len <= 0) {
            throw new IllegalArgumentException("ERROR: PASSWORD LENGTH LESS THAN 0!");
        }

        if (len <= 6 && len > 0) {
            System.out.println("SECURITY WARNING: PASSWORD WEAK (< 7 Characters)");
        }

        //VALID INPUT FUNCTIONALITY 
        arr = new int[len]; //Creates new array to store integers
        for (int i = 0; i < len; i++) { //Collects integers
            arr[i] = r.nextInt(70);
        }

        StringBuilder s = new StringBuilder(); //String Builder for our password
        for (int i = 0; i < len; i++) { //Creates password array
            s.append(letters[arr[i]]); //Appends the corresponding letter
        }
        password = s.toString(); //Creates password properly

        return password; //Returns the password
    }


    /**
     * Adds a new password entry object to the vault
     * Encrypts the plaintext password with raw vault key
     * Service and username are not encrypted, but are included as additional authenticated data
     *
     * @param service  service name 
     * @param username username for the service
     * @param password plaintext password
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void addPasswordEntry(String service, String username, String plaintextPassword) throws GeneralSecurityException, IOException {
        
        // Generate a new IV for this password entry
        byte[] entryIV = CryptoUtils.generateRandomBytes(12);

        // Construct the additional authenticated data (AAD) for the encryption
        String aadString = service + ":" + username;
        byte[] aad = aadString.getBytes(StandardCharsets.UTF_8);

        // Encrypt the plaintext password using the raw vault key and the newly generated IV
        String encryptedPassword;
        try {
            encryptedPassword = CryptoUtils.encryptAESGCMWithAAD(
                    plaintextPassword.getBytes(StandardCharsets.UTF_8),
                    rawVaultKey,
                    entryIV,
                    aad
            );
        } catch (Exception e) {
            throw new GeneralSecurityException("Error encrypting password entry", e);
        }

        // Create a new PasswordEntry object and add it to the vault data
        PasswordEntry newEntry = new PasswordEntry(
                Base64.getEncoder().encodeToString(entryIV),
                service,
                username,
                encryptedPassword
        );

        // Add the new entry to the vault data and save the updated vault to disk.
        vaultData.getPasswords().add(newEntry);

        JsonHandler.saveVault(vaultData);

        System.out.println("Password entry added.");
    }


    /**
     * Looks up the password entry for a given service and username,
     * then decrypts the stored encrypted password using AES-GCM with AAD.
     *
     * @param service   service name 
     * @param username  username for the service
     * @return          decrypted plaintext password, or service not found
     * @throws GeneralSecurityException 
     */
    public String lookupPassword(String service, String username) throws GeneralSecurityException {

        // iterate through the stored password entries in the vault
        for (PasswordEntry entry : vaultData.getPasswords()) {

            // check if both the service and username match the lookup criteria.
            if (entry.getService().equals(service) && entry.getUser().equals(username)) {

                // Retrieve the IV for this password entry (Base64-decoded)
                byte[] entryIV = Base64.getDecoder().decode(entry.getIv());

                // Construct the Additional Authenticated Data from service and username
                String aadString = service + ":" + username;
                byte[] aad = aadString.getBytes(StandardCharsets.UTF_8);

                // try to decrypt the stored encrypted password using the raw vault key, IV, and aad
                try {

                    byte[] decryptedBytes = CryptoUtils.decryptAESGCMWithAAD(entry.getPass(), rawVaultKey, entryIV, aad);

                    // turn the returned bytes back into a string and return this constructed plaintext password
                    return new String(decryptedBytes, StandardCharsets.UTF_8);

                } catch (Exception e) {
                    throw new GeneralSecurityException("Error decrypting password for service: " + service, e);
                }
            }
        }
        return "Service not found.";
    }
    
    /**
     * Adds a new privateKeyEntry object to the vault data
     * Encrypts the provided private key using the raw vault key,
     * then stores it along with the service name
     *
     * @param service     service name associated with the private key
     * @param privateKey  private key bytes to be encrypted then stored
     * @throws GeneralSecurityException 
     * @throws IOException              
     */
    public void addPrivateKeyEntry(String service, byte [] privateKey) throws GeneralSecurityException, IOException {

        // Generate new IV for private key encryption before storing it
        byte[] entryIV = CryptoUtils.generateRandomBytes(12);
        
        // Encrypt the plaintext private key using the raw vault key and the generated IV
        String encryptedPrivateKey;
        try {
            encryptedPrivateKey = CryptoUtils.encryptAESGCM(
                privateKey,
                rawVaultKey,
                entryIV
            );

        } catch (Exception e) {

            throw new GeneralSecurityException("Error encrypting private key entry", e);
        }
        
        // Create a new PrivateKeyEntry object.
        // Note: IV is stored in Base64 format; the service name remains in plaintext.
        PrivateKeyEntry entry = new PrivateKeyEntry(
            Base64.getEncoder().encodeToString(entryIV),
            service,
            encryptedPrivateKey
        );
        
        // Add the new entry to the in-memory list of private key entries.
        vaultData.getPrivkeys().add(entry);
        
        // Save the updated vault data back to disk.
        JsonHandler.saveVault(vaultData);
        
        System.out.println("Private key entry added.");
    }

    /** 
     * Generate ElGamal key pair and store the private key in the vault, displaying the public key to the user
     * 
     * @param service - service name associated with the key pair
     * @throws Exception
     */
    public void addNewElGamal(String service) throws Exception {

    // Generate a 512-bit ElGamal key pair using the new CryptoUtils method
    KeyPair elGamalKeyPair = CryptoUtils.generateElGamalKeyPair();
    
    // Convert the public key to a Base64 string to display to the user
    String publicKeyBase64 = Base64.getEncoder().encodeToString(elGamalKeyPair.getPublic().getEncoded());
    
    // get the private key bytes from the key pair
    byte[] privateKeyBytes = elGamalKeyPair.getPrivate().getEncoded();
    
    // Encrypt and store the private key using your existing method for private keys
    addPrivateKeyEntry(service, privateKeyBytes);
    
    // Output the public key so the user can use it as needed
    System.out.println("ElGamal Public Key (Base64): " + publicKeyBase64);
    }


    /**
     * Lookup an Elgamal private key given a service name and output as a Base64 encoded string.
     * 
     * @param args
     */
    public String lookupElGamalPrivateKey(String service) throws GeneralSecurityException {

        // Iterate through the stored private key entries in the vault
        for (PrivateKeyEntry entry : vaultData.getPrivkeys()) {

            // Check if the service matches the given service
            if (entry.getService().equals(service)) {

                // Retrieve the IV for this private key entry (Base64-decoded)
                byte[] entryIV = Base64.getDecoder().decode(entry.getIv());
                // Try to decrypt the stored encrypted private key using the raw vault key and IV
                try {
                    byte[] decryptedBytes = CryptoUtils.decryptAESGCM(
                        Base64.getDecoder().decode(entry.getPrivkey()),
                        rawVaultKey,
                        entryIV
                    );

                    // Turn the returned bytes back into a string and return this constructed plaintext private key
                    return Base64.getEncoder().encodeToString(decryptedBytes);
                } catch (Exception e) {
                    throw new GeneralSecurityException("Error decrypting private key for service: " + service, e);
                }
            }
        }
        return "Service not found.";
    }
}