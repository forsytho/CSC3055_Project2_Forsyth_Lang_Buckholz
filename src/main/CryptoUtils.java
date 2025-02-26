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
    private static int GCM_TAG_LENGTH = 128;
    private static final int IV_SIZE = 12; //Recommended IV size for AES-GCM

    //Generate rendom bytes (for IVs, salts, keys)
    public static byte[] generateRandomBytes(int size){
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    //Generate a random IV for AES-GCM
    public static byte[] generateIV(){
        return generateRandomBytes(IV_SIZE);
    }

    //Encrypt data using AES-GCM
    public static String encryptAESGCM(byte[] data, byte[] key, byte[] iv) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKey secretKey = new SecretKeySpec(key, AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encryptData = cipher.doFinal(data);

        return Base64.getEncoder().encodeToString(encryptData);
    }

    //Decrypt data using AES-GCM
    public static byte[] decryptAESGCM(byte[] encryptedData, byte[] key, byte[] iv) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKey secretKey = new SecretKeySpec(key, AES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        return cipher.doFinal(encryptedData);
    }

    //Generate a random AES key
    public static byte[] generateAESKey(int keySize) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }
}
