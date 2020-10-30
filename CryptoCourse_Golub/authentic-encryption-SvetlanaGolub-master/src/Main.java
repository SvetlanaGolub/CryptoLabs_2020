import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class Main {

    private static final int encryptMode = 1;
    private static final int decryptMode = 2;
    private static final int blockSize = 16;
    private static final int KBIn1MB = 1024;
    private static final int bytesIn1KB = 1024;
    private static final int MB = 100;
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\authentic-encryption-SvetlanaGolub\\src\\results\\Result";

    public static void main(String[] args) throws Exception {
        int bytesIn100MB = MB * bytesIn1KB * KBIn1MB;

        byte[] key = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(key);

        byte[] data = new byte[bytesIn100MB];
        new Random().nextBytes(data);

        //Зашифровываем данные
        Authentication authentication = new Authentication(encryptMode);
        authentication.SetKey(key);
        byte[] encrypted = authentication.ProcessData(data);
        authentication.reset();

        //Сравниваем hmac и расшифровываем данные
        authentication = new Authentication(decryptMode);
        authentication.SetKey(key);
        byte[] decrypt = authentication.ProcessData(encrypted);
        authentication.reset();

        //сравниваем данные с изначальными
        dataCheck(data, decrypt);

    }

    public static void dataCheck(byte[] data, byte[] result) throws IOException {
        FileWriter writer = new FileWriter(file_path, true);
        boolean check = Arrays.equals(data, result);
        writer.write('\n' + "Result equals to the original data? " + '\t' + check + '\n');
        writer.flush();
    }
}
