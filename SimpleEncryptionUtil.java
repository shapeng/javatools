/**
* Simple Encryption/Decryption Utility.
* Reference : http://www.oracle.com/technetwork/java/javase/tech/index-jsp-136007.html
**/
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
 
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
 
import org.apache.commons.codec.binary.Base64;
 
public class SimpleEncryptionUtil {
    private static final String ENCRYPTION_KEY = "GuessWhat!";
    private static final int PBE_ITERATIONS = 20;
    private static final byte[] SALT = {
        (byte) 0xde, (byte) 0x23, (byte) 0x10, (byte) 0x17,
        (byte) 0xde, (byte) 0x23, (byte) 0x10, (byte) 0x17,
    };
 
    /**
     * Returns a (fixed) salted PBEWithMD5AndDES hash of the password.
     *
     * @param   password    the password to hash
     * @return              a salted MD5 hash of the password
     * @throws GeneralSecurityException, UnsupportedEncodingException
     */
    public static String encrypt(String property) throws GeneralSecurityException, UnsupportedEncodingException {
        return encrypt(property, ENCRYPTION_KEY);
    }
     
    /**
     * Returns a (fixed) salted PBEWithMD5AndDES hash of the password.
     *
     * @param   password    the password to hash
     * @param   publicKey   the encryption key to generate hash
     * @return              a salted MD5 hash of the password
     * @throws GeneralSecurityException, UnsupportedEncodingException
     */
    public static String encrypt(String property, String publicKey) throws GeneralSecurityException, UnsupportedEncodingException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(publicKey.toCharArray()));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(SALT, PBE_ITERATIONS));
        return base64Encode(pbeCipher.doFinal(property.getBytes("UTF-8")));
    }
 
    /**
     * Returns a String in UTF-8 encoding.
     *
     * @param   bytes       a byte array
     * @return              a String in UTF-8 encoding
     * @throws UnsupportedEncodingException
     */
    private static String base64Encode(byte[] bytes) throws UnsupportedEncodingException {
        return new String(Base64.encodeBase64(bytes), "UTF-8");
    }
 
    /**
     * Returns decrypted password using (fixed) salted PBEWithMD5AndDES hash algorithm.
     *
     * @param   password    the password in hash using PBEWithMD5AndDES
     * @return              the decrypted password
     * @throws GeneralSecurityException, IOException
     */
    public static String decrypt(String property) throws GeneralSecurityException, IOException {
        return decrypt(property, ENCRYPTION_KEY);
    }
     
    /**
     * Returns decrypted password using (fixed) salted PBEWithMD5AndDES hash algorithm.
     *
     * @param   password    the password in hash using PBEWithMD5AndDES
     * @param   publicKey   the encryption key used to generate hash
     * @return              the decrypted password
     * @throws GeneralSecurityException, IOException
     */
    public static String decrypt(String property, String publicKey) throws GeneralSecurityException, IOException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(publicKey.toCharArray()));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(SALT, PBE_ITERATIONS));
        return new String(pbeCipher.doFinal(base64Decode(property)), "UTF-8");
    }
 
    /**
     * Returns a byte array.
     *
     * @param   property    a String in UTF-encoding
     * @return              a byte array
     * @throws IOException
     */
    private static byte[] base64Decode(String property) throws IOException {
        return Base64.decodeBase64(property.getBytes("UTF-8"));
    }
 
     
    /***
     * Advanced password security using PBKDF2WithHmacSHA1 algorithm  *
     **/
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
 
    private static final int SALT_BYTE_SIZE = 24;
    private static final int HASH_BYTE_SIZE = 24;
    private static final int PBKDF2_ITERATIONS = 1000;
 
    private static final int ITERATION_INDEX = 0;
    private static final int SALT_INDEX = 1;
    private static final int PBKDF2_INDEX = 2;
     
    private static final byte[] FIXED_SALT = {
        (byte) 0xde, (byte) 0x23, (byte) 0x10, (byte) 0x17,
        (byte) 0x17, (byte) 0xde, (byte) 0x23, (byte) 0x10,
        (byte) 0x10, (byte) 0x17, (byte) 0xde, (byte) 0x23,
        (byte) 0x23, (byte) 0x10, (byte) 0x17, (byte) 0xde,
    };
     
    /**
     * Returns a (fixed) salted PBKDF2 hash of the password.
     *
     * @param   password    the password to hash
     * @return              a salted PBKDF2 hash of the password (UTF-8 encoding)
     * @throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException
     */
    public static String generatePasswordFixedSalt(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
        byte[] hash = pbkdf2(password.toCharArray(), FIXED_SALT, PBKDF2_ITERATIONS, FIXED_SALT.length);
        return PBKDF2_ITERATIONS + ":" + toHex(FIXED_SALT) + ":" + (new String(Base64.encodeBase64(hash), "UTF-8"));
    }
     
    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param   password    the password to hash
     * @return              a salted PBKDF2 hash of the password
     * @throws NoSuchAlgorithmException, InvalidKeySpecException
     */
    public static String generatePasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return generatePasswordHash(password.toCharArray());
    }
 
    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param   password    the password to hash
     * @return              a salted PBKDF2 hash of the password
     * @throws NoSuchAlgorithmException, InvalidKeySpecException
     */
    public static String generatePasswordHash(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a random salt
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[SALT_BYTE_SIZE];
        random.nextBytes(salt);
 
        // Hash the password
        byte[] hash = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
        // format iterations:salt:hash
        return PBKDF2_ITERATIONS + ":" + toHex(salt) + ":" +  toHex(hash);
    }
 
    /**
     * Validates a password using a hash.
     *
     * @param   password        the password to check
     * @param   correctHash     the hash of the valid password
     * @return                  true if the password is correct, false if not
     * @throws NoSuchAlgorithmException, InvalidKeySpecException
     */
    public static boolean validatePassword(String password, String correctHash) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return validatePassword(password.toCharArray(), correctHash);
    }
 
    /**
     * Validates a password using a hash.
     *
     * @param   password        the password to check
     * @param   correctHash     the hash of the valid password
     * @return                  true if the password is correct, false if not
     * @throws NoSuchAlgorithmException, InvalidKeySpecException
     */
    public static boolean validatePassword(char[] password, String correctHash) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Decode the hash into its parameters
        String[] params = correctHash.split(":");
        int iterations = Integer.parseInt(params[ITERATION_INDEX]);
        byte[] salt = fromHex(params[SALT_INDEX]);
        byte[] hash = fromHex(params[PBKDF2_INDEX]);
        // Compute the hash of the provided password, using the same salt, iteration count, and hash length
        byte[] testHash = pbkdf2(password, salt, iterations, hash.length);
        // Compare the hashes in constant time. The password is correct if both hashes match.
        return slowEquals(hash, testHash);
    }
 
    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     *
     * @param   a       the first byte array
     * @param   b       the second byte array
     * @return          true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for(int i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
 
    /**
     *  Computes the PBKDF2 hash of a password.
     *
     * @param   password    the password to hash.
     * @param   salt        the salt
     * @param   iterations  the iteration count (slowness factor)
     * @param   bytes       the length of the hash to compute in bytes
     * @return              the PBDKF2 hash of the password
     * @throws NoSuchAlgorithmException, InvalidKeySpecException
     */
    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }
 
    /**
     * Converts a string of hexadecimal characters into a byte array.
     *
     * @param   hex         the hex string
     * @return              the hex string decoded into a byte array
     */
    private static byte[] fromHex(String hex) {
        byte[] binary = new byte[hex.length() / 2];
        for(int i = 0; i < binary.length; i++) {
            binary[i] = (byte)Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }
        return binary;
    }
 
    /**
     * Converts a byte array into a hexadecimal string.
     *
     * @param   array       the byte array to convert
     * @return              a length*2 character string encoding the byte array
     */
    private static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
 
 
    /*** MAIN ***/
    public static void main(String[] args) throws Exception {
        String originalPassword = "secret password";
        System.out.println("Original password: " + originalPassword);
         
        // PBEWithMD5AndDES with fixed SALT
        String encryptedPassword = encrypt(originalPassword);
        System.out.println("[PBEWithMD5AndDES] Encrypted: " + encryptedPassword);
        String decryptedPassword = decrypt(encryptedPassword);
        System.out.println("[PBEWithMD5AndDES] Decrypted: " + decryptedPassword);
 
        // PBKDF2WithHmacSHA1 with fixed SALT
        String encryptPass = generatePasswordFixedSalt(originalPassword);
        System.out.println("[PBKDF2WithHmacSHA1] Encrypted(fixed Salt): " + encryptPass);
 
        // PBKDF2WithHmacSHA1 with random SALT
        String generatedSecuredPasswordHash = generatePasswordHash(originalPassword);
        System.out.println("[PBKDF2WithHmacSHA1] Encrypted: " + generatedSecuredPasswordHash);
        boolean matched = validatePassword(originalPassword, generatedSecuredPasswordHash);
        System.out.println("[PBKDF2WithHmacSHA1] Validate: " + (matched? "Passed":"Failed"));
    }

}
