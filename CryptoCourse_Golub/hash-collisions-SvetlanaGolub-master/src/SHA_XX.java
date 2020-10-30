import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;

public class SHA_XX {

    private static final String hash_method = "SHA-256";
    private static final int from_index = 0;
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static byte[] sha_xx(byte[] value, int hash_size) throws NoSuchAlgorithmException {
        byte[] bitToByte;
        MessageDigest messageDigest = MessageDigest.getInstance(hash_method);
        value = messageDigest.digest(value);
        bitToByte = first_xx_bits(value, from_index, hash_size);
        messageDigest.reset();
        return bitToByte;
        //return FirstXXbits.string_first_xx_bits(value, from_index, hash_size);
    }

    public static byte[] first_xx_bits (byte[] value, int from_index, int xx){
        byte[] bytes_from_bits;
        BitSet all_bits_from_key = BitSet.valueOf(value);
        BitSet needed_bits = all_bits_from_key.get(from_index, xx);

        bytes_from_bits = needed_bits.toByteArray();
        return bytes_from_bits;
    }

    public static String byte_to_hex(byte[] bytes){
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
