import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class OFB {

    private static final int blockSize = 16;
    private static final int ivSize = 16;
    private static final int encryptMode = 1;
    private static boolean specialPadding = false;

    public static byte[] ofbEncrypt(byte[] plainText, byte[] iv, byte[] key)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        AES aes = new AES();
        aes.setCipher(encryptMode, key);
        ByteArrayOutputStream b = new ByteArrayOutputStream(plainText.length + blockSize);
        b.write(iv); //добавляем в начало шифртекста iv
        int count = (int) Math.ceil((double) plainText.length / blockSize); //количество блоков
        int start = 0;
        int end = blockSize;
        byte[] input = iv;
        for (int i = 0; i < count; i++) {
            //берём следующий блок открытого текста
            byte[] block = Arrays.copyOfRange(plainText, start, end);
            byte[] cipherInput = aes.AesBlockEncrypt(input, specialPadding);
            input = cipherInput;//на вход следующему блоку подаём результат предыдущего
            byte[] cipherBlock = Operations.xor(block, cipherInput);
            //если блок последний дополняем недостающие байты
            if (block.length < blockSize){
                cipherBlock = Operations.padding(cipherBlock);
            }
            b.write(cipherBlock);
            start = end;
            end = start + blockSize;
            if (end > plainText.length)
                end = plainText.length;
        }
        //результат конкатинации блоков
        return b.toByteArray();
    }

    public static byte[] ofbDecrypt(byte[] cipherText, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        AES aes = new AES();
        aes.setCipher(encryptMode, key);
        ByteArrayOutputStream b = new ByteArrayOutputStream(cipherText.length - blockSize);
        byte[] iv = Arrays.copyOf(cipherText, ivSize);
        cipherText = Arrays.copyOfRange(cipherText, ivSize, cipherText.length);
        int count = (int) Math.ceil((double) cipherText.length / blockSize); //количество блоков
        int start = 0;
        int end = blockSize;
        byte[] input = iv;
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(cipherText, start, end);
            //если блок последний, убираем padding
            if (end == cipherText.length) {
                block = Operations.nopadding(block);
            }
            byte[] cipherInput = aes.AesBlockDecrypt(input, specialPadding);
            input = cipherInput;
            byte[] plainBlock = Operations.xor(cipherInput, block);
            b.write(plainBlock);
            start = end;
            end = start + blockSize;
        }
        //результат конкатинации блоков
        return b.toByteArray();
    }
}
