import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class AES {

    private Cipher cipher;

    private static final String mode = "AES/ECB/NoPadding";
    private static final String algorithm = "AES";
    private static final int blockSize = 16;

    public AES() {
    }

    public void setCipher(int MODE, byte[] key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Key secretKeySpec = new SecretKeySpec(key, algorithm);
        cipher = Cipher.getInstance(mode);
        cipher.init(MODE, secretKeySpec);
    }

    public byte[] AesBlockEncrypt(byte[] data, Main.Mode mode, boolean specialPadding) throws Exception {
        byte[] encryptedData;
        if (data.length < blockSize)
            specialPadding = true;
        // дополняем блок, если нужно
        if (specialPadding) {
            data = Operations.padding(data, mode);
        }
        encryptedData = cipher.doFinal(data);
        return encryptedData;
    }
}

