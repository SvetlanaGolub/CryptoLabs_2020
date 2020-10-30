import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CheckCipher {

    private static final String algorithm = "AES";
    private static final int ivSize = 16;
    private static final int encryptMode = 1;
    private static final int decryptMode = 2;
    private static final String mode = "AES/CBC/NoPadding";
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\blockciphers-SvetlanaGolub\\src\\results\\Results";

    public static byte[] cbcEncryption(byte[] key, byte[] data, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        FileWriter writer = new FileWriter(file_path, true);
        writer.write("\n\t" + "Standard CBC Encryption realisation: " + '\n');
        ByteArrayOutputStream b = new ByteArrayOutputStream(data.length + iv.length);
        Key secretKeySpec = new SecretKeySpec(key, algorithm);
        Cipher cipher = Cipher.getInstance(mode);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(encryptMode, secretKeySpec, ivParameterSpec);
        b.write(iv);
        b.write(cipher.doFinal(data));
        writer.write("Cipher Text: " + Hex.encodeHexString(b.toByteArray()) + '\n');
        writer.flush();
        return b.toByteArray();
    }

    public static byte[] cbcDecryption(byte[] key, byte[] data) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        FileWriter writer = new FileWriter(file_path, true);
        Key secretKeySpec = new SecretKeySpec(key, algorithm);
        writer.write("\n\t" + "Standard CBC Decryption realisation " + '\n');
        byte[] iv = Arrays.copyOf(data, ivSize);
        data = Arrays.copyOfRange(data, ivSize, data.length);
        Cipher cipher = Cipher.getInstance(mode);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(decryptMode, secretKeySpec, ivParameterSpec);
        writer.write("Plain Text: " + new String(cipher.doFinal(data)) + '\n');
        writer.flush();
        return cipher.doFinal(data);
    }
}