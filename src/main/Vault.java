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

public class Vault {
    private static final String VAULT_FILE = "vault.json";
    private static final int SCRYPT_COST = 2048;
    private static final int SCRYPT_BLOCK_SIZE = 8;
    private static final int SCRYPT_PARALLELIZATION = 1;
    private static final int SCRYPT_KEY_LENGTH = 32; // AES-256

    private VaultData vaultData;
    private byte[] vaultKey;

    public Vault(String password) throws GeneralSecurityException, IOException {
        if (!new File(VAULT_FILE).exists()) {
            createNewVault(password);
        } else {
            loadExistingVault(password);
        }
    }

    private void createNewVault(String password) throws GeneralSecurityException, IOException {
        System.out.println("Creating a new vault...");

        // Generate a new random salt
        byte[] salt = CryptoUtils.generateRandomBytes(16);
        String encodedSalt = Base64.getEncoder().encodeToString(salt);

        // Derive vault key using scrypt
        vaultKey = deriveKey(password, salt);

        // Generate random vault encryption key
        byte[] vaultEncryptionKey = CryptoUtils.generateRandomBytes(32);
        byte[] iv = CryptoUtils.generateRandomBytes(12);

        // Encrypt the vault encryption key using the vault key
        String encryptedVaultKey = CryptoUtils.encryptAESGCM(vaultEncryptionKey, vaultKey, iv);

        // Initialize vault data
        vaultData = new VaultData(encodedSalt, new VaultKey(Base64.getEncoder().encodeToString(iv), encryptedVaultKey));

        saveVault();
        System.out.println("Vault successfully created.");
    }

    private void loadExistingVault(String password) throws GeneralSecurityException, IOException {
        System.out.println("Loading existing vault...");

        ObjectMapper objectMapper = new ObjectMapper();
        vaultData = objectMapper.readValue(new File(VAULT_FILE), VaultData.class);

        byte[] salt = Base64.getDecoder().decode(vaultData.getSalt());
        vaultKey = deriveKey(password, salt);

        byte[] iv = Base64.getDecoder().decode(vaultData.getVaultKey().getIv());
        byte[] encryptedKey = Base64.getDecoder().decode(vaultData.getVaultKey().getKey());

        byte[] decryptedKey = CryptoUtils.decryptAESGCM(encryptedKey, vaultKey, iv);
        vaultKey = decryptedKey; // Use decrypted vault key for further operations

        System.out.println("Vault successfully unsealed.");
    }

    private byte[] deriveKey(String password, byte[] salt) {
        return SCrypt.generate(password.getBytes(StandardCharsets.UTF_8), salt, SCRYPT_COST, SCRYPT_BLOCK_SIZE, SCRYPT_PARALLELIZATION, SCRYPT_KEY_LENGTH);
    }

    public void addPasswordEntry(String service, String user, String password) throws GeneralSecurityException, IOException {
        byte[] iv = CryptoUtils.generateRandomBytes(12);
        String encryptedPassword = CryptoUtils.encryptAESGCM(password.getBytes(StandardCharsets.UTF_8), vaultKey, iv);
        vaultData.getPasswords().add(new PasswordEntry(Base64.getEncoder().encodeToString(iv), service, user, encryptedPassword));

        saveVault();
        System.out.println("Password entry added.");
    }

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

    private void saveVault() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(new File(VAULT_FILE), vaultData);
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter vault password: ");
            String password = scanner.nextLine();

            Vault vault = new Vault(password);

            while (true) {
                System.out.println("\n1. Add Password\n2. Lookup Password\n3. Exit");
                System.out.print("Choose an option: ");
                String input = scanner.nextLine();
                int choice;
                try{
                    choice = Integer.parseInt(input);
                } catch (NumberFormatException e){
                    choice = -1;
                }

                switch (choice) {
                    case 1:
                        System.out.print("Service: ");
                        String service = scanner.nextLine();
                        System.out.print("Username: ");
                        String user = scanner.nextLine();
                        System.out.print("Password: ");
                        String pass = scanner.nextLine();

                        vault.addPasswordEntry(service, user, pass);
                        break;

                    case 2:
                        System.out.print("Service to lookup: ");
                        service = scanner.nextLine();
                        System.out.println("Password: " + vault.lookupPassword(service));
                        break;

                    case 3:
                        System.out.println("Exiting...");
                        return;

                    default:
                        System.out.println("Invalid option.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
