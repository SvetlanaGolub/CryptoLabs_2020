import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    public static final int blockSize = 16;
    private static final int nonceSize = 12;
    private static final int counterSize = 4;
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\blockciphers-SvetlanaGolub\\src\\results\\Results";

    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IOException, DecoderException, ShortBufferException, InvalidAlgorithmParameterException {

        String cbcKeyString = "140b41b22a29beb4061bda66b6747e14";
        byte[] cbcKey = Hex.decodeHex(cbcKeyString.toCharArray());
        String cbcCipherTextString1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
        byte[] cbcCipherText1  = Hex.decodeHex(cbcCipherTextString1.toCharArray());
        String cbcCipherTextString2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
        byte[] cbcCipherText2  = Hex.decodeHex(cbcCipherTextString2.toCharArray());

        String ctrKeyString = "36f18357be4dbd77f050515c73fcf9f2";
        byte[] ctrKey = Hex.decodeHex(ctrKeyString.toCharArray());
        String ctrCipherTextString1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
        byte[] ctrCipherText1  = Hex.decodeHex(ctrCipherTextString1.toCharArray());
        String ctrCipherTextString2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
        byte[] ctrCipherText2  = Hex.decodeHex(ctrCipherTextString2.toCharArray());

        FileWriter writer = new FileWriter(file_path, true);
        writer.write("Task № 2.5 - Comparing CBC cipher" + '\n');
        writer.flush();

        byte[] KeyCheck = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(KeyCheck);
        byte[] ivCheck = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(ivCheck);
        byte[] dataCheck = "Now we need to compare my CBC with standard CBC ".getBytes(StandardCharsets.UTF_8);

        byte[] cipherTextCheck1 = AesEncrypt(KeyCheck, dataCheck, "CBC", ivCheck);
        byte[] cipherTextCheck2 = CheckCipher.cbcEncryption(KeyCheck, dataCheck, ivCheck);
        if (Arrays.equals(cipherTextCheck1, cipherTextCheck2))
            writer.write('\n' + "The same result!!!" + '\n');
        else
            writer.write('\n' + "Something go wrong :(" + '\n');
        writer.flush();

        byte[] plainTextCheck1 = AesDecrypt(KeyCheck, cipherTextCheck1, "CBC");
        byte[] plainTextCheck = CheckCipher.cbcDecryption(KeyCheck, cipherTextCheck2);
        if (Arrays.equals(plainTextCheck1, plainTextCheck))
            writer.write('\n' + "The same result!!!" + '\n');
        else
            writer.write('\n' + "Something go wrong :(" + '\n');
        writer.flush();

        writer.write("\n\n" +"Task № 3 - Decryption" + '\n');
        writer.flush();

        AesDecrypt(cbcKey, cbcCipherText1, "CBC");
        AesDecrypt(cbcKey, cbcCipherText2, "CBC");

        AesDecrypt(ctrKey, ctrCipherText1, "CTR");
        AesDecrypt(ctrKey, ctrCipherText2, "CTR");

        writer.write("\n\n" + "Task № 4 - Encryption of two and a half blocks" + '\n');
        writer.flush();
        byte[] key = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(key);
        byte[] iv = new byte[blockSize];
        byte[] data = "Now we need to encrypt two and a half blocks.".getBytes(StandardCharsets.UTF_8);

        byte[] ecbCipherText = AesEncrypt(key, data, "ECB", null);
        AesDecrypt(key, ecbCipherText, "ECB");

        SecureRandom.getInstanceStrong().nextBytes(iv);
        byte[] cbcCipherText = AesEncrypt(key, data, "CBC", iv);
        AesDecrypt(key, cbcCipherText, "CBC");

        SecureRandom.getInstanceStrong().nextBytes(iv);
        byte[] cfbCipherText = AesEncrypt(key, data, "CFB", iv);
        AesDecrypt(key, cfbCipherText, "CFB");

        SecureRandom.getInstanceStrong().nextBytes(iv);
        byte[] ofbCipherText = AesEncrypt(key, data, "OFB", iv);
        AesDecrypt(key, ofbCipherText, "OFB");

        //определяем iv для режими CTR
        //первая часть - случайный nonce
        //вторая часть - счётчик (начинается с номера первого блока)
        byte[] nonce = new byte[nonceSize];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        int startBlock = 1;
        byte[] counter = ByteBuffer.allocate(counterSize).putInt(startBlock).array();
        System.arraycopy(nonce, 0, iv, 0, nonceSize);
        System.arraycopy(counter, 0, iv, nonceSize, counterSize);

        byte[] ctrCipherText = AesEncrypt(key, data, "CTR", iv);
        AesDecrypt(key, ctrCipherText, "CTR");

    }

    public static byte[] AesEncrypt(byte[] key, byte[] data, String mode, byte[] iv)
            throws BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, IOException, ShortBufferException {
        FileWriter writer = new FileWriter(file_path, true);
        writer.write("\n\t" + mode + " Encryption" + '\n');
        writer.write("Text to encrypt: " + new String(data) + '\n');
        byte[] cipherText = new byte[blockSize];
        switch (mode) {
            case ("ECB"):
                cipherText = ECB.ecbEncrypt(data, key);
                break;
            case ("CBC"):
                cipherText = CBC.cbcEncrypt(data, iv, key);
                break;
            case ("CFB"):
                cipherText = CFB.cfbEncrypt(data, iv, key);
                break;
            case ("OFB"):
                cipherText = OFB.ofbEncrypt(data, iv, key);
                break;
            case ("CTR"):
                cipherText = CTR.ctrEncrypt(data, iv, key);
                break;
        }
        writer.write("Cipher Text: " + Hex.encodeHexString(cipherText) + '\n');
        writer.flush();
        return cipherText;
    }

    public static byte[] AesDecrypt(byte[] key, byte[] data, String mode)
            throws BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, IOException, ShortBufferException {
        FileWriter writer = new FileWriter(file_path, true);
        writer.write("\n\t" + mode + " Decryption" + '\n');
        byte[] plainText = new byte[blockSize];
        switch (mode) {
            case ("ECB"):
                plainText = ECB.ecbDecrypt(data, key);
                break;
            case ("CBC"):
                plainText = CBC.cbcDecrypt(data, key);
                break;
            case ("CFB"):
                plainText = CFB.cfbDecrypt(data, key);
                break;
            case ("OFB"):
                plainText = OFB.ofbDecrypt(data, key);
                break;
            case ("CTR"):
                plainText = CTR.ctrDecrypt(data, key);
                break;
        }
        writer.write("Plain Text: " + new String(plainText) + '\n');
        writer.flush();
        return plainText;
    }

}
