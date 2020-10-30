import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class AES {

    private Cipher cipher;

    private static final String mode = "AES/ECB/NoPadding";
    private static final String algorithm = "AES";

    public AES() {
    }

    public void setCipher(int MODE, byte[] key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Key secretKeySpec = new SecretKeySpec(key, algorithm);
        cipher = Cipher.getInstance(mode);
        cipher.init(MODE, secretKeySpec);
    }

    public byte[] AesBlockEncrypt(byte[] data, boolean specialPadding) throws  BadPaddingException, IllegalBlockSizeException {
        byte[] encryptedData;
        //для шифров, в которых шифртекст проходит через блок шифрования
        if (specialPadding) {
            data = Operations.padding(data);
        }
        encryptedData = cipher.doFinal(data);
        return encryptedData;
    }

    public byte[] AesBlockDecrypt(byte[] data, boolean specialPadding) throws BadPaddingException, IllegalBlockSizeException {
        byte[] decryptedData;
        decryptedData = cipher.doFinal(data);
        //для шифров, в которых шифртекст проходит через блок шифрования
        if (specialPadding) {
            decryptedData = Operations.nopadding(decryptedData);
        }
        return decryptedData;
    }

}
