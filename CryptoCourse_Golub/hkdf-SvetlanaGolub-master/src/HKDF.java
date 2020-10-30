import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class HKDF {

    private static byte[] last_key = null;
    private static final List<byte[]> hkdf_keys = new ArrayList<>();

    public static List<byte[]> get_hkdf_keys(byte[] XTS, byte[] data, byte[] CTX, int number_of_keys) throws IOException, NoSuchAlgorithmException {
        byte[] prk = HkdfExtract(XTS, data);
        for (int j = 0; j < number_of_keys; j++) {
            hkdf_keys.add(j, HkdfExpand(prk, last_key, CTX, j));
            last_key = hkdf_keys.get(j);
        }
        return hkdf_keys;
    }

    //получаем ключ PRK для псевдослучайной функции
    public static byte[] HkdfExtract(byte[] XTS, byte[] SKM) throws IOException, NoSuchAlgorithmException {
        return HMAC.HmacSha256(XTS, SKM);
    }

    public static byte[] HkdfExpand(byte[] PRK, byte[] lastKey, byte[] CTX, int i) throws IOException, NoSuchAlgorithmException {
        byte[] i_to_byte = Integer.toString(i).getBytes(StandardCharsets.UTF_8);
        byte[] hkdf_key;
        if (i == 0) {
            hkdf_key = HMAC.HmacSha256(PRK, CTX);
        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(lastKey.length + CTX.length + i_to_byte.length);
            baos.write(lastKey);
            baos.write(CTX);
            baos.write(i_to_byte);
            byte[] ctx_plus_i = baos.toByteArray();
            hkdf_key = HMAC.HmacSha256(PRK, ctx_plus_i);
        }
        return hkdf_key;
    }
}


