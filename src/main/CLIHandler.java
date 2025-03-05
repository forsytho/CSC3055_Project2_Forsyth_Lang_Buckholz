import java.util.Scanner;
import java.nio.charset.StandardCharsets;

/**
 * Handles command line interface for the vault application
 */
public class CLIHandler {
    private final Vault vault;
    private final Scanner scanner;

    public CLIHandler(Vault vault) {
        this.vault = vault;
        this.scanner = new Scanner(System.in);
    }

    /**
     * Starts the CLI loop
     */
    public void start() {
        while (true) {
            System.out.println("\nVault CLI Menu:");
            System.out.println("1. Add Password Entry");
            System.out.println("2. Lookup Password");
            System.out.println("3. Add Random Password Entry");
            System.out.println("4. Add Private Key Entry");
            System.out.println("5. Lookup ElGamal Private Key");
            System.out.println("6. Add Generated ElGamal Key Pair");
            System.out.println("7. Exit");
            System.out.print("Choose an option: ");

            String input = scanner.nextLine();
            int choice;
            try {
                choice = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a number.");
                continue;
            }

            try {
                switch (choice) {
                    case 1:
                        addPasswordEntry();
                        break;
                    case 2:
                        lookupPassword();
                        break;
                    case 3:
                        addRandomPasswordEntry();
                        break;
                    case 4:
                        addPrivateKeyEntry();
                        break;
                    case 5:
                        lookupElGamalPrivateKey();
                        break;
                    case 6:
                        addGeneratedElGamalKeyPair();
                        break;
                    case 7:
                        System.out.println("Exiting CLI.");
                        return;
                    default:
                        System.out.println("Invalid option. Try again.");
                }
            } catch (Exception e) {
                System.err.println("Operation failed: " + e.getMessage());
            }
        }
    }

    /**
     * Add a service, username, password triple to vault
     * 
     * @throws Exception
     */
    private void addPasswordEntry() throws Exception {

        System.out.print("Enter service name: ");
        String service = scanner.nextLine();

        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        vault.addPasswordEntry(service, username, password);
    }

    /**
     * Lookup a password for a given service and username
     * 
     * @throws Exception
     */
    private void lookupPassword() throws Exception {

        System.out.print("Enter service name: ");
        String service = scanner.nextLine();

        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        String result = vault.lookupPassword(service, username);
        System.out.println("Decrypted Password: " + result);
    }

    /**
     * Enter a service, username, and randomly generated password to the vault
     * 
     * @throws Exception
     */
    private void addRandomPasswordEntry() throws Exception {

        System.out.print("Enter service name: ");
        String service = scanner.nextLine();

        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter desired password length: ");
        int length = Integer.parseInt(scanner.nextLine());

        vault.addRandomPasswordEntry(length, service, username);
        System.out.println("Random password entry added");
    }

    /**
     * Add a private key entry to the vault
     * @throws Exception
     */
    private void addPrivateKeyEntry() throws Exception {

        System.out.print("Enter service name for private key: ");
        String service = scanner.nextLine();

        System.out.print("Enter private key (plaintext): ");
        String key = scanner.nextLine();

        vault.addPrivateKeyEntry(service, key.getBytes(StandardCharsets.UTF_8));
        System.out.println("Private key entry added");
    }

    /**
     * lookup an ElGamal private key from the vault
     * 
     * @throws Exception
     */
    private void lookupElGamalPrivateKey() throws Exception {

        System.out.print("Enter service name: ");
        String service = scanner.nextLine();
        String result = vault.lookupElGamalPrivateKey(service);
        System.out.println("ElGamal Private Key (Base64): " + result);
    }

    /**
     * Add a newly generated ElGamal key pair to the vault
     * 
     * @throws Exception
     */
    private void addGeneratedElGamalKeyPair() throws Exception {

        System.out.print("Enter service name for new ElGamal key pair: ");
        String service = scanner.nextLine();
        vault.addNewElGamal(service);
    }
}
