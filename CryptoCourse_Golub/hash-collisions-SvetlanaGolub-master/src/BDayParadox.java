import javafx.util.Pair;
import org.apache.commons.codec.binary.Hex;

import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BDayParadox {

    private static final int size_of_input = 16;
    private static final int number_of_collisions = 100;
    private static final int bits_in_byte = 8;
    public static final int number_of_ints = 5;
    public static final int size_of_int = 4;
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\hash-collisions-SvetlanaGolub\\src\\Collisions\\BDayCollisions";

    public static void get_collisions(int xx) throws NoSuchAlgorithmException, IOException {
        long time = System.currentTimeMillis();
        List<Pair<byte[], byte[]>> list_of_values = new ArrayList<>();

        boolean collision_found = false;
        int collision_count = 0;
        FileWriter writer = new FileWriter(file_path, true);

        do {
            byte[] input = new byte[size_of_input];
            SecureRandom.getInstanceStrong().nextBytes(input);

            byte[] hash_input = SHA_XX.sha_xx(input, xx);

            Pair<byte[], byte[]> new_pair = new Pair<>(input, hash_input);
            for (Pair<byte[], byte[]> pair : list_of_values) {
                if (Arrays.equals(pair.getValue(), new_pair.getValue())) {
                    writer.write("Collision " + (collision_count + 1) + '\n');
                    writer.write('\t' + Hex.encodeHexString(pair.getValue()) + " <-- " + Hex.encodeHexString(pair.getKey()) + '\n');
                    writer.write('\t' + Hex.encodeHexString(new_pair.getValue()) + " <-- " + Hex.encodeHexString(new_pair.getKey()));
                    writer.append('\n');
                    writer.flush();
                    collision_found = true;
                    collision_count++;
                    break;
                }
            }
            if (!collision_found)
                list_of_values.add(new_pair);

        } while (collision_count != number_of_collisions);
        int memory_size = list_of_values.size() * (size_of_input + xx / bits_in_byte) + number_of_ints * size_of_int;
        writer.write("Время выполнения: " + (int) (System.currentTimeMillis() - time) + " милисекунд");
        writer.write("\nЗатраты по памяти: " + memory_size + " байт");
        writer.flush();
        System.out.println();
    }

}
