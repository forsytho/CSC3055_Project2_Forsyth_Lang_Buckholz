import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;

/**
 * Handles reading and writing of JSON 
 */
public class JsonHandler {

    private static final String VAULT_FILE = "vault.json";
    private static final ObjectMapper objectMapper = new ObjectMapper();


    /**
     * Saves the VaultData object to vault.json as a JSON object
     * This includes the salt, encrypted vaultKey, and encrypted secrets
     * 
     * @param vaultData
     */
    public static void saveVault(VaultData vaultData){

        // Check if vaultData is null
        if(vaultData == null){
            System.err.println("Error: Vault data is null. Cannot save.");
            return;
        }

        //  Write the VaultData object to vault.json
        //  If the file does not exist, it will be created
        try{

            objectMapper.writerWithDefaultPrettyPrinter().writeValue(new File(VAULT_FILE), vaultData);
            System.out.println("Vault successfully saved.");

        } catch (IOException e){

            System.err.println("Error saving vault.json.");
            e.printStackTrace();
        }
    }



    /**
     * Loads only the salt and vault key from vault.json, both being the only required fields for authentication
     * Prevents loading of encrypted secrets to memory before authentication
     * 
     * @return
     */
    public static VaultData loadVaultMetadata() {
        File file = new File(VAULT_FILE);
    
        // Check if vault.json exists
        if (!file.exists()) {
            System.out.println("No existing vault found.");
            return null;  // Vault doesn't exist
        }
    
        try {
            // Read only the required fields from JSON
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode root = objectMapper.readTree(file);
    
            // Extract salt
            String salt = root.get("salt").asText();
    
            // Extract vault key object (IV + encrypted vault key)
            JsonNode vaultKeyNode = root.get("vaultKey");
            String iv = vaultKeyNode.get("iv").asText();
            String encryptedKey = vaultKeyNode.get("key").asText();
    
            VaultKey vaultKey = new VaultKey(iv, encryptedKey);
    
            // Return a minimal VaultData object with only the necessary info
            return new VaultData(salt, vaultKey);
    
        } catch (IOException e) {
            System.err.println("Error loading vault metadata. The file may be corrupted.");
            return null;
        }
    }


    /**
     * Loads text from vault.json into a VaultData object, 
     * Which contains salt, vaultKey, and encrypted passwords and private keys
     * 
     * @return vaultData - VaultData object containing salt, vaultKey, and encrypted secrets
     */
    public static VaultData loadVault(){

        File file = new File(VAULT_FILE);
        if(!file.exists()){
            System.out.println("No existing vault found. Creating a new vault.");
            return null; //The Vault class should handle this and create a new vault.
        }

        try{
            return objectMapper.readValue(file, VaultData.class);
        } catch (IOException e){
            System.err.println("Error loading vault.json,  file may be corrupted.");
            return null;
        }
    }
}
