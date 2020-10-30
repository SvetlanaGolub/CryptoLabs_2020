import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class ECB {

    private static final int blockSize = 16;
    private static final int encryptMode = 1;
    private static final int decryptMode = 2;

    public static byte[] ecbEncrypt(byte[] data, byte[] key)
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IOException {
        AES aes = new AES();
        aes.setCipher(encryptMode, key);
        ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length + 1);// +1 контрольный бит для последнего блока
        int count = (int) Math.ceil((double) data.length / blockSize);
        int start = 0;
        int end = blockSize;
        boolean isFinalBlock = false;
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(data, start, end);
            byte[] encryptBlock = aes.AesBlockEncrypt(block, isFinalBlock);
            baos.write(encryptBlock);
            start = end;
            if (start + blockSize >= data.length) {
                end = data.length;
                isFinalBlock = true;
            } else end = start + blockSize;
        }
        //результат конкатинации блоков
        return baos.toByteArray();
    }

    public static byte[] ecbDecrypt(byte[] data, byte[] key)
            throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        AES aes = new AES();
        aes.setCipher(decryptMode, key);
        int decryptedBlockSize = blockSize;
        int start = 0;
        int end = decryptedBlockSize;
        boolean isFinalBlock = false;
        int count = (int) Math.ceil((double) (data.length - 1) / decryptedBlockSize); //количество блоков
        if (count == 1)
            isFinalBlock = true;
        ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(data, start, end);
            byte[] decryptBlock = aes.AesBlockDecrypt(block, isFinalBlock);
            baos.write(decryptBlock);
            start = end;
            end = start + decryptedBlockSize;
            if (end == data.length) {
                isFinalBlock = true;
            }
        }
        //результат конкатинации блоков
        return baos.toByteArray();
    }
}

