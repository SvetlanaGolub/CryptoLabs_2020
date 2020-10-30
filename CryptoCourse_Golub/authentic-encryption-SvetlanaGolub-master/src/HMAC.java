import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMAC {

    private static final String algorithm = "HmacSHA256";
    private static final int keySize = 16;

    public static byte[] getHMAC(byte[] cipherText, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] toChangeKey = "data to change..".getBytes(StandardCharsets.UTF_8);
        byte[] hmac;
        for (int i = 0; i < keySize; i++) {
            toChangeKey[i] ^= key[i];
        }
        Mac mac = Mac.getInstance(algorithm);
        SecretKeySpec hmacKey = new SecretKeySpec(toChangeKey, algorithm);
        mac.init(hmacKey);
        hmac = mac.doFinal(cipherText);
        mac.reset();
        return hmac;
    }
}
