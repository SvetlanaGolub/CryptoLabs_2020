import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CBC {

    private static final int blockSize = 16;
    private static final int ivSize = 16;
    private static final int encryptMode = 1;
    private static final int decryptMode = 2;

    public static byte[] cbcEncrypt(byte[] plainText, byte[] iv, byte[] key)
            throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(plainText.length + blockSize);
        b.write(iv); // добавляем iv в начало шифртекста
        AES aes = new AES();
        aes.setCipher(encryptMode, key);
        int count = (int) Math.ceil((double) plainText.length / blockSize);
        int start = 0;
        int end = blockSize;
        byte[] forXor = iv;
        boolean isFinalBlock = false;
        if (count == 1)
            isFinalBlock = true;
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(plainText, start, end);
            byte[] ivXorPt = Operations.xor(forXor, block);
            byte[] encryptBlock = aes.AesBlockEncrypt(ivXorPt, isFinalBlock);
            b.write(encryptBlock); //конкатинируем блоки в конечный cipherText
            forXor = encryptBlock; //на функцию xor теперь подаём предыдущий блок
            start = end;
            end = start + blockSize;
            if (end > plainText.length) {
                end = plainText.length;
                isFinalBlock = true;
            }
        }
        //результат конкатинации блоков
        return b.toByteArray();
    }

    public static byte[] cbcDecrypt(byte[] cipherText, byte[] key)
            throws IOException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(cipherText.length - blockSize);
        AES aes = new AES();
        aes.setCipher(decryptMode, key);
        int decryptSize = blockSize;
        int start = 0;
        int end = decryptSize;
        byte[] iv = Arrays.copyOf(cipherText, ivSize);
        cipherText = Arrays.copyOfRange(cipherText, blockSize, cipherText.length);
        int count = (int) Math.ceil((double) (cipherText.length - 1) / decryptSize);
        boolean isFinalBlock = false;
        if (count == 1)
            isFinalBlock = true;
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(cipherText, start, end);
            byte[] decryptBlock = aes.AesBlockDecrypt(block, isFinalBlock);
            byte[] ivXorBlock = Operations.xor(iv, decryptBlock);
            b.write(ivXorBlock); // конкатинируем блоки в один
            iv = block;
            start = end;
            end = start + decryptSize;
            if (end == cipherText.length) {
                isFinalBlock = true;
            }
        }
        //результат конкатинации блоков
        return b.toByteArray();
    }
}
