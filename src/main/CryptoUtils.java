import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {
    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_SIZE = 12; // Recommended IV size for AES-GCM

    // Generate random bytes (for IVs, salts, keys)
    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static byte[] generateIV(){
        return generateRandomBytes(IV_SIZE);
    }



    /**
     * Encrypt data using AES-GCM, return as Base64
     * 
     * @param data - data to be encrypted
     * @param key - key to encrypt data with
     * @param iv - given initialization vector
     * @return - encrypted data in Base64 format
     * @throws Exception
     */
    public static String encryptAESGCM(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKey secretKey = new SecretKeySpec(key, AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encryptedData = cipher.doFinal(data);

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Decrypt data using AES-GCM
    public static byte[] decryptAESGCM(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKey secretKey = new SecretKeySpec(key, AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        return cipher.doFinal(encryptedData);
    }


    /**
     * Encrypts data using AES-GCM with Additional Authenticated Data 
     *
     * @param data      plaintext data to encrypt
     * @param key       encryption key
     * @param iv        initialization vector
     * @param aad       additional authenticated data (e.g., service name, username)
     * @return          Base64-encoded encrypted data
     * @throws Exception  
     */
    public static String encryptAESGCMWithAAD(byte[] data, byte[] key, byte[] iv, byte[] aad) throws Exception {

        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);

        byte[] encryptedData = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    /**
     * Decrypts data using AES-GCM with Additional Authenticated Data 
     *
     * @param encryptedBase64  Base64-encoded encrypted data
     * @param key              encryption key
     * @param iv               initialization vector
     * @param aad              additional authenticated data (has to be same as used during encryption)
     * @return                 decrypted plaintext bytes
     * @throws Exception 
     */
    public static byte[] decryptAESGCMWithAAD(String encryptedBase64, byte[] key, byte[] iv, byte[] aad) throws Exception {

        byte[] encryptedData = Base64.getDecoder().decode(encryptedBase64);
        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);

        return cipher.doFinal(encryptedData);
    }

    /** 
     * Generate a random AES key
     */
    public static byte[] generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }


    /**
     * Generates a random password of the specified length
     *
     * @param length  desired length of the password
     * @return        randomly generated password
     * @throws IllegalArgumentException 
     */
    public static String generateRandomPassword(int length) {

        if (length <= 0) {
            throw new IllegalArgumentException("Password length must be greater than zero");
        }
        if (length < 7) {
            System.out.println("Warning: a password length of less than 7 is not recommended for security purposes");
        }
        
        // Define the allowed character set
        final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#$%!&*@?";
        
        // Create a SecureRandom instance for random number generation
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);
        
        

        // for: the length of password, generate a random index and select the character at that index, add to password string
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(CHARACTERS.length());
            password.append(CHARACTERS.charAt(index));
        }
        
        return password.toString();
    }




}
