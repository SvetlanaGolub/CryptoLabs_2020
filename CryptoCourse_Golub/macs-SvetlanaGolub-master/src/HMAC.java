import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HMAC {
    private static final byte opad = 0x5c;
    private static final byte ipad = 0x36;
    private static final String hash_method = "SHA-256";
    private static final String ivString = "0123456789abcdfe";



    public static byte[] hmacEncryptBlock(byte[] data, byte[] key) throws NoSuchAlgorithmException, IOException {
        MessageDigest messageDigest = MessageDigest.getInstance(hash_method);
        byte[] blockHash;
        blockHash = messageDigest.digest(Operations.concatTwoParts(key, data));
        return blockHash;
    }
// получаем первый и второй ключи, ксоря основной ключ с ipad и opad соответственно
    public static byte[] getKey1(byte[] key){
        return Operations.xorPad(key, ipad);
    }

    public static byte[] getKey2(byte[] key){
        return Operations.xorPad(key, opad);
    }

    // хэшируем ключи, сконкатинированные с iv, чтобы получить финальные ключи
    public static byte[] getFinalKey(byte[] key) throws DecoderException, IOException, NoSuchAlgorithmException {
        byte[] iv = Hex.decodeHex(ivString.toCharArray());
        byte[] concat = Operations.concatTwoParts(iv, key);
        MessageDigest messageDigest = MessageDigest.getInstance(hash_method);
        return messageDigest.digest(concat);
    }
}
