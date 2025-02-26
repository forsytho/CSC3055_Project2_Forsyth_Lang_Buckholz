import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;

public class JsonHandler {
    private static final String VAULT_FILE = "vault.json";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    //Load vault data from JSON
    public static VaultData loadVault(){
        File file = new File(VAULT_FILE);
        if(!file.exists()){
            System.out.println("No existing vault found. Creating a new vault.");
            return null; //The Vault class should handle this and create a new vault.
        }

        try{
            return objectMapper.readValue(file, VaultData.class);
        } catch (IOException e){
            System.err.println("Error loading vault.json. The file may be corrupted.");
            return null;
        }
    }

    //Save vault data to JSON
    public static void saveVault(VaultData vaultData){
        if(vaultData == null){
            System.err.println("Error: Vault data is null. Cannot save.");
            return;
        }

        try{
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(new File(VAULT_FILE), vaultData);
            System.out.println("Vault successfully saved.");
        } catch (IOException e){
            System.err.println("Error saving vault.json.");
            e.printStackTrace
        }
    }
    
}
