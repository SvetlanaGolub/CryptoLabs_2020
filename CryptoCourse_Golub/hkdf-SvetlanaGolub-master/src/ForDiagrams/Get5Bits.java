package ForDiagrams;

import java.util.BitSet;

public class Get5Bits {

    public static String get_bits(byte[] key, int from_index, int number_of_bits){
        StringBuilder bits = new StringBuilder();
        BitSet all_bits_from_key = BitSet.valueOf(key);
        BitSet needed_bits = all_bits_from_key.get(from_index, number_of_bits);

        for (int i = 0; i < number_of_bits; i++){
            if (needed_bits.get(i)) {
                bits.append("1");
                //System.out.print("1");
            }
            else bits.append("0");
                //System.out.print("0");
        }
        System.out.print(" ");
        return String.valueOf(bits);
    }
}
