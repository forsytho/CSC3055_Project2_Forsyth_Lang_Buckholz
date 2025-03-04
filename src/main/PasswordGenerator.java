import java.security.SecureRandom;

public class PasswordGenerator {
    //MEMBER VARIABLES
    private String password;
    private SecureRandom r = new SecureRandom();
    private char[] letters = {'#', '$', '%', '!', '&', '*', '@', '?', 
                            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                            'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
                            'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                            't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', 
                            '3', '4', '5', '6', '7', '8', '9', '0'};
    private int[] arr;

    //PASSWORD GENERATOR
    public String genPass(int len) {
        //WARNINGS / BREAK
        if (len <= 0) {
            System.out.println("PASSWORD GENERATION FAILED! MESSAGE LENGTH TOO SHORT");
            return "";
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
}