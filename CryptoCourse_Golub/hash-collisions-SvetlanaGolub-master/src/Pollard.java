import org.apache.commons.codec.binary.Hex;

import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.BitSet;

public class Pollard {
    private final int thread;
    private int current_iter;
    private long current_time;
    private static final byte zero = 0x00;
    private static final int hash_size = 16;
    public static final int thread_number = 2;
    private static final int log_base = 2;
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\hash-collisions-SvetlanaGolub\\src\\Collisions\\PollardCollisions";

    public Pollard(int thread, int current_iter) {
        this.thread = thread;
        this.current_iter = current_iter;
    }

    public long getCurrent_time(){
        return current_time;
    }

/*
    public List<PointInfo> get_collisions(int collision_count, List<PointInfo> pointInfo_list) throws NoSuchAlgorithmException, IOException {

        System.out.println("Thread: " + thread);
        GetResult get_indexes = collision_index(current_start, pointInfo_list);
        get_indexes.print();
        compare(get_indexes, current_start, another_start, collision_count);
        return pointInfo_list;
    }

*/
    public static void compare(GetResult result, byte[] current, byte[] another, int collision_count) throws NoSuchAlgorithmException, IOException {
        FileWriter writer = new FileWriter(file_path, true);
        int difference = Math.abs(result.getFirst_index() - result.getSecond_index());
        int iter = 0;
        byte[] hash_current;
        byte[] hash_another;
        if (result.getSame_thread())//если хэши нашли в одном потоке
            another = current;
        if (result.getFirst_index() > result.getSecond_index()) {
            current = prepare_values(difference, current);
        } else another = prepare_values(difference, another);
        while (true) {
            iter++;
            hash_current = SHA_XX.sha_xx(current, hash_size);
            hash_another = SHA_XX.sha_xx(another, hash_size);
            if (Arrays.equals(hash_current, hash_another)) {
                writer.write("Collision " + (collision_count) + '\n');
                writer.write('\t' + Hex.encodeHexString( hash_current ) + " <-- " + Hex.encodeHexString( current ) + '\n');
                writer.write('\t' + Hex.encodeHexString( hash_another ) + " <-- " + Hex.encodeHexString( another ));
                writer.append('\n');
                writer.flush();
                return;
            }
            current = hash_current;
            another = hash_another;
        }
    }

    public static byte[] prepare_values(int difference, byte[] value) throws NoSuchAlgorithmException {
        for (int i = 0; i < difference; i++)
            value = SHA_XX.sha_xx(value, hash_size);
        return value;
    }

    //возвращаем отличительную точку
    public PointInfo get_point(byte[] point, long start_time) throws NoSuchAlgorithmException {
        //считаем вемя, которое потоки тратят на поиск точек
        while (true) {
            current_iter++;
            point = SHA_XX.sha_xx(point, hash_size);
            point = concatenation(point);
            boolean distinguished_point = true;
            //int q = (int) ((hash_size / 2) - (Math.log(thread_number) / Math.log(log_base)));
            int q = 5; // по формуде выходит 7, но при таком раскладе программа работает слишком долго
            BitSet bits = BitSet.valueOf(point);
            for (int i = 0; i < q; i++) {
                distinguished_point = !bits.get(i);//перемножаем первые биты
                if(!distinguished_point)
                    break;
            }
            if (distinguished_point)
                current_time += (System.currentTimeMillis() - start_time);
                return new PointInfo(current_iter, point, thread);
        }
    }

    public byte[] concatenation(byte[] value) {
        byte[] new_value = new byte[value.length + 1];
        System.arraycopy(value, 0, new_value, 0, value.length);
        new_value[new_value.length - 1] = zero;

        return new_value;
    }


}


        /*BitSet all_bits = BitSet.valueOf(value);
        int result_size = Byte.SIZE * value.length + number_zero;
        byte[] concat = new byte[result_size];
        BitSet concat_bits = new BitSet(result_size);
        for (int i = 0; i < result_size; i++) {
            if (all_bits.get(i) && (i < all_bits.length())) {
                concat_bits.set(i);
            } else concat_bits.set(i, false);
        }
        //concat_bits.set(result_size - 1);
        concat = concat_bits.toByteArray();*/