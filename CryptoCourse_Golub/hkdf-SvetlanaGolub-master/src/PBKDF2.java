import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class PBKDF2 {

    private static int len_of_hmac = 32;
    private static byte[] last_hmac = null;
    private static final int number_of_hmac = 1000;

    public static byte[] pbkdf(byte[] salt, byte[] password, int number_of_blocks) throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(len_of_hmac * number_of_blocks);
        for (int i = 0; i < number_of_blocks; i++) {
            baos.write(xor_all_iter(salt, password, i + 1));
        }
        byte[] final_result = baos.toByteArray();
        baos.reset();
        return final_result;
    }


    public static byte[] concat_salt_and_i(byte[] salt, int i) throws IOException {
        byte[] i_to_byte = Integer.toString(i).getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream baos = new ByteArrayOutputStream(salt.length + i_to_byte.length);
        baos.write(salt);
        baos.write(i_to_byte);
        byte[] concat = baos.toByteArray();
        baos.reset();
        return concat;
    }

    public static byte[] xor_hmac(byte[] last_hmac, byte[] actual_hmac) {
        byte[] xor_two_hmac = new byte[len_of_hmac];
        for (int i = 0; i < len_of_hmac; i++) {
            xor_two_hmac[i] = (byte) (last_hmac[i] ^ actual_hmac[i]);
        }
        return xor_two_hmac;
    }

    public static byte[] xor_all_iter(byte[] salt, byte[] password, int iter) throws IOException, NoSuchAlgorithmException {
        byte[] xor_all = new byte[len_of_hmac];
        if (last_hmac == null) {
            last_hmac = HMAC.HmacSha256(password, concat_salt_and_i(salt, iter));
            xor_all = last_hmac;
        }
        for (int i = 1; i < number_of_hmac; i++) {
            byte[] actual_hmac = HMAC.HmacSha256(password, last_hmac);
            xor_all = xor_hmac(xor_all, actual_hmac);
            last_hmac = actual_hmac;
        }
        return xor_all;
    }


}