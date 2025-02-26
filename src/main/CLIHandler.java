import java.io.Console;
import java.util.Scanner;

public class CLIHandler {
    private final Vault vault;
    private final Scanner scanner;
    private final Console console;

    public CLIHandler(Vault vault){
        this.vault = vault;
        this.scanner = new Scanner(System.in);
        this.console = System.console();
    }

    public void start(){
        while(true){
            System.out.println("\n1. Add Password\n2. Lookup Password\n3. Exit");
            System.out.print("Choose an option: ");

            String input = scanner.nextLine();
            int choice;
            try{
                choice = Integer.parseInt(input);
            } catch (NumberFormatException e){
                System.out.println("Invalid input. Please enter a number.");
                continue;
            }

            switch(choice){
                case 1:
                    handleAddPassword();
                    break;
                case 2:
                    handleLookupPassword();
                    break;
                case 3:
                    System.out.println("Exiting...");
                    return;
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
    }

    private void handleAddPassword(){
        System.out.print("Service: ");
        String service = scanner.nextLine();
        System.out.print("Username: ");
        String user = scanner.nextLine();

        String pass;
        if(console != null){
            pass = new String(console.readPassword("Enter Password: "));
        } else{
            System.out.print("Enter Password: ");
            pass = scanner.nextLine();
        }

        try{
            vault.addPasswordEntry(service,user,pass);
            System.out.println("Password added successfully.");
        } catch (Exception e){
            System.err.println("Error adding password.");
            e.printStackTrace();
        }
    }

    private void handleLookupPassword(){
        System.out.print("Service to lookup: ");
        String service = scanner.nextLine();

        try{
            String password = vault.lookupPassword(service);
            System.out.println("Password: " + password);
        } catch(Exception e){
            System.err.println("Error retrieving password.");
            e.printStackTrace();
        }
    }
    
}
