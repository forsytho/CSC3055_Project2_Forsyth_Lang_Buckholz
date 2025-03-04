import java.io.Console;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Console console = System.console();
        String password = null;
        Vault vault = null;
        
        // Loop until a valid password is provided and the vault is successfully loaded/unsealed
        while (vault == null) {

            if (console != null) {

                password = new String(console.readPassword("Vault Password: "));

            } else {

                System.out.print("Vault Password: ");
                password = scanner.nextLine();

            }
            
            // try to create or load the vault
            try {
                
                vault = new Vault(password); 

                break; // Exit loop when the vault is loaded
                
            } catch (Exception e) {

                System.err.println("Authentication failed: " + e.getMessage());
                System.err.println("Please try again.\n");

                vault = null; // Ensure vault remains null so loop continues
            }
        }

        scanner.close();
        
        // Once authenticated, pass the vault to the CLI handler.
        CLIHandler cli = new CLIHandler(vault);
        cli.start();
    }
}

