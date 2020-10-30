import org.apache.commons.codec.binary.Hex;

import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main {

    private static final int hash_size = 16;
    public static final int start_size = 2;
    public static final int number_of_collisions = 100;
    private static long time = 0;
    private static int list_size = 0;
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\hash-collisions-SvetlanaGolub\\src\\Collisions\\PollardCollisions";
    private static final int point_size = 24;
    private static final int constants_size = 60;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

        BDayParadox.get_collisions(hash_size);

        int collision_count = 0;
        do {
            collision_count++;
            byte[] first_start = new byte[start_size];
            SecureRandom.getInstanceStrong().nextBytes(first_start);
            byte[] second_start = new byte[start_size];
            SecureRandom.getInstanceStrong().nextBytes(second_start);

            MultiThread multiThread = new MultiThread();
            multiThread.get_collision(first_start, second_start, collision_count);
            list_size = Math.max(list_size, multiThread.getList_size());
            time += multiThread.getMinus_time();
        } while (collision_count != number_of_collisions);
        FileWriter writer = new FileWriter(file_path, true);
        writer.write("Время выполнения: " + (int) time + " милисекунд");
        int memory_size = list_size * point_size + constants_size;
        writer.write("\nЗатраты по памяти: " + memory_size + " байт");
        writer.flush();
    }
}
