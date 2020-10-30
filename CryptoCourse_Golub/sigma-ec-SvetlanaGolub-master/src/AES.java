import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AES {

    private static final String algorithm = "AES";
    private static final String mode = "AES/CTR/NoPadding";
    private static final String macAlgorithm = "HmacSHA256";
    private static final int encryptMode = 1;
    private static final int decryptMode = 2;
    private static final int ivSize = 16;

    public static byte[] getMac(byte[] cipherText, byte[] key) throws Exception {
        if (key == null)
            throw new Exception("Define key for mac first");
        Mac mac = Mac.getInstance(macAlgorithm);
        SecretKeySpec macKey = new SecretKeySpec(key, macAlgorithm);
        mac.init(macKey);
        //берём мак от нашего шифртекста
        return mac.doFinal(cipherText);
    }

    public static void checkMac(byte[] mac, byte[] cipherText, byte[] key) throws Exception {
        boolean check = Arrays.equals(getMac(cipherText, key), mac);
        if (!check)
            throw new Exception("Wrong mac. Authentication failed!");
    }

    public static byte[] encrypt(byte[] message, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = new byte[ivSize];
        SecretKeySpec aesKey = new SecretKeySpec(key, algorithm);
        Cipher cipher = Cipher.getInstance(mode);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(encryptMode, aesKey, ivParameterSpec);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(iv);
        b.write(cipher.doFinal(message));
        return b.toByteArray();
    }

    public static byte[] decrypt(byte[] cipherText, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);
        byte[] iv = Arrays.copyOf(cipherText, ivSize);
        cipherText = Arrays.copyOfRange(cipherText, ivSize, cipherText.length);
        Cipher cipher = Cipher.getInstance(mode);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(decryptMode, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(cipherText);
    }
}
