import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CTR {

    private static final int blockSize = 16;
    private static final int ivSize = 16;
    private static final int encryptMode = 1;
    private static boolean specialPadding = false;

    public static byte[] ctrEncrypt(byte[] plainText, byte[] iv, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        AES aes = new AES();
        aes.setCipher(encryptMode, key);
        ByteArrayOutputStream b = new ByteArrayOutputStream(plainText.length + blockSize);
        b.write(iv);
        int count = (int) Math.ceil((double) plainText.length / blockSize); //количество блоков
        int start = 0;
        int end = blockSize;
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(plainText, start, end);
            byte[] cipherIv = aes.AesBlockEncrypt(iv, specialPadding);
            byte[] cipherBlock = Operations.xor(block, cipherIv);
            //если блок последний дополняем недостающие байты
            /*if (block.length < blockSize)
                cipherBlock = Operations.padding(cipherBlock);*/
            b.write(cipherBlock);
            start = end;
            end = start + blockSize;
            if (end > plainText.length)
                end = plainText.length;
            iv[blockSize - 1] ++; //увеличиваем счётчик блоков
        }
        //результат конкатинации блоков
        return b.toByteArray();
    }

    public static byte[] ctrDecrypt(byte[] cipherText, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        AES aes = new AES();
        aes.setCipher(encryptMode, key);
        ByteArrayOutputStream b = new ByteArrayOutputStream(cipherText.length - blockSize);
        byte[] iv = Arrays.copyOf(cipherText, ivSize);
        cipherText = Arrays.copyOfRange(cipherText, ivSize, cipherText.length);
        int count = (int) Math.ceil((double) cipherText.length / blockSize); //количество блоков
        int start = 0;
        int end = blockSize;
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(cipherText, start, end);
            byte[] cipherIv = aes.AesBlockEncrypt(iv, specialPadding);
            byte[] plainBlock = Operations.xor(block, cipherIv);
            //если блок последний, убираем padding
            /*if (end == cipherText.length)
                plainBlock = Operations.nopadding(plainBlock);*/
            b.write(plainBlock);
            start = end;
            end = start + blockSize;
            if (end > cipherText.length)
                end = cipherText.length;
            iv[blockSize - 1] ++; //увеличиваем сётчик блоков
        }
        //результат конкатинации блоков
        return b.toByteArray();
    }
}
