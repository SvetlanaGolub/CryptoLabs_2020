import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HMAC {
    private static final byte opad = 0x5c;
    private static final byte ipad = 0x36;
    private static final int block_size = 64;
    private static final byte zero_byte = 0x0;
    private static final String hash_method = "SHA-256";


    public static byte[] HmacSha256(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, IOException {
//если ключ больше размера блока, хэшируем его
        MessageDigest messageDigest = MessageDigest.getInstance(hash_method);

        if (key.length > block_size) {
            key = messageDigest.digest(key);
            messageDigest.reset();
        }
// key xor opad
        byte[] key_xor_opad = new byte[block_size];
        for (int i = 0; i < block_size; i++) {
            if (i < key.length) {
                key_xor_opad[i] = (byte) (key[i] ^ opad);
            } else key_xor_opad[i] = zero_byte;
        }
// key xor ipad
        byte[] key_xor_ipad = new byte[block_size];
        for (int i = 0; i < block_size; i++) {
            if (i < key.length) {
                key_xor_opad[i] = (byte) (key[i] ^ ipad);
            } else key_xor_opad[i] = zero_byte;
        }
//конкатинируем (key xor ipad) и data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(key_xor_ipad);
        baos.write(data);
        byte[] key_xor_ipad_plus_data = baos.toByteArray();
        baos.reset();
//хэшируем то, что сконкатинировали выше
        byte[] hash_key_xor_ipad_plus_data = messageDigest.digest(key_xor_ipad_plus_data);
        messageDigest.reset();
//конкатинируем все массивы байт
        baos.write(key_xor_opad);
        baos.write(hash_key_xor_ipad_plus_data);
        byte[] concat_all = baos.toByteArray();
//хэшируем сконкатинированные элементы
        byte[] final_hmac = messageDigest.digest(concat_all);
        messageDigest.reset();

        return final_hmac;
    }

}
