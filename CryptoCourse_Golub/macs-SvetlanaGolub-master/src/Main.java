import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;

public class Main {

    enum Mode {OMAC, tMAC, HMAC}

    private static final int bitToChange = 17;
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\macs-SvetlanaGolub\\src\\result\\results";
    private static final int for01KB = 100;
    private static final int for1KB = 1024;
    private static final int for10KB = 10240;
    private static final int for1024KB = 1048576;

    public static void main(String[] args) throws Exception {
        byte[] key = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(key);
        byte[] data = "We need to encrypt two and a half blocks.".getBytes(StandardCharsets.UTF_8);
        System.out.println(Arrays.toString(data));

        FileWriter writer = new FileWriter(file_path, true);
        writer.write("Task № 3 - Calculate and verify tag" + '\n');
        writer.flush();

        byte[] omacTag = getTag(data, key, Mode.OMAC);
        check(data, key, omacTag, Mode.OMAC);
        byte[] hmacTag = getTag(data, key, Mode.HMAC);
        check(data, key, hmacTag, Mode.HMAC);
        byte[] tmacTag = getTag(data, key, Mode.tMAC);
        check(data, key, tmacTag, Mode.tMAC);

        writer.write('\n' + "Task № 3.1 - Different data" + '\n');
        writer.flush();

        byte[] changedData = changData(data);

        omacTag = getTag(data, key, Mode.OMAC);
        check(changedData, key, omacTag, Mode.OMAC);
        hmacTag = getTag(data, key, Mode.HMAC);
        check(changedData, key, hmacTag, Mode.HMAC);
        tmacTag = getTag(data, key, Mode.tMAC);
        check(changedData, key, tmacTag, Mode.tMAC);

        writer.write('\n' + "Task № 4 - Productivity" + "\n\n");
        writer.flush();

        countTime(for01KB, key, Mode.OMAC);
        countTime(for1KB,key, Mode.OMAC);
        countTime(for10KB,key, Mode.OMAC);
        countTime(for1024KB,key, Mode.OMAC);
        countTime(for01KB, key, Mode.HMAC);
        countTime(for1KB,key, Mode.HMAC);
        countTime(for10KB,key, Mode.HMAC);
        countTime(for1024KB,key, Mode.HMAC);

    }

    public static byte[] getTag(byte[] data, byte[] key, Mode mode) throws Exception {
        FileWriter writer = new FileWriter(file_path, true);
        writer.write("\n\t" + mode.toString());
        MAC mac = new MAC(mode);
        mac.SetKey(key);
        byte[] tag = mac.ComputeMac(data);
        writer.write("\n\t" + "Tag: " + Arrays.toString(tag) + '\n');
        writer.flush();
        return tag;
    }

    public static void check(byte[] data, byte[] key, byte[] tag, Mode mode) throws Exception {
        FileWriter writer = new FileWriter(file_path, true);
        MAC mac = new MAC(mode);
        mac.SetKey(key);
        boolean isTheSame = mac.VerifyMac(data, tag);
        writer.write('\t' + "Is verification passed?  " + isTheSame + '\n');
        writer.flush();
    }

    public static byte[] changData(byte[] data) {
        BitSet bitSet = BitSet.valueOf(data);
        bitSet.flip(bitToChange);
        return bitSet.toByteArray();
    }

    public static void countTime(int n, byte[] key, Mode mode) throws Exception {
        for (int i = 0; i < 1000; i++) {
            SecureRandom.getInstanceStrong().nextBytes(key);
            String randomString = RandomString.getAlphaNumericString(n);
            byte[] randomData = randomString.getBytes(StandardCharsets.UTF_8);
            double time = System.currentTimeMillis();
            byte[] tag = getTag(randomData, key, mode);
            System.out.print(System.currentTimeMillis() - time + ", ");
        }
        System.out.println();
    }

}
