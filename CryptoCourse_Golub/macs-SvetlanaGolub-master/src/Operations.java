import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.BitSet;

public class Operations {

    private static final int blockSize = 16;
    private static final byte zero = 0x00;
    private static final byte one = 0x01;
    private static final int byteSize = 8;

    public static byte[] xor(byte[] firstValue, byte[] secondValue) {
        int resultSize = Math.min(firstValue.length, secondValue.length);
        byte[] xorValue = new byte[resultSize];
        for (int i = 0; i < resultSize; i++) {
            xorValue[i] = (byte) (firstValue[i] ^ secondValue[i]);
        }
        return xorValue;
    }

    public static byte[] concatTwoParts(byte[] first, byte[] second) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(first);
        b.write(second);
        return b.toByteArray();
    }

    public static byte[] xorPad(byte[] key, byte pad) {
        byte[] resKey = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            if (i < key.length) {
                resKey[i] = (byte) (key[i] ^ pad);
            } else resKey[i] = zero;
        }
        return resKey;
    }


    //дополняем недостоющие байты в последнем блоке
    public static byte[] padding(byte[] block, Main.Mode mode) throws Exception {
        int extra = blockSize - block.length;
        byte[] paddedBlock = Arrays.copyOf(block, blockSize);
        switch (mode) {
            case OMAC:
                // дополняем 1 и всеми нулями далее
                paddedBlock[block.length] = one;
                for (int i = 1; i < extra; i++) {
                    paddedBlock[blockSize - extra] = zero;
                }
                break;
            case tMAC:
                for (int i = 0; i < extra; i++) {
                    paddedBlock[blockSize - 1 - i] = (byte) extra;
                }
                break;
            default:
                throw new Exception("encryption mode mode" + mode + "is not supported");
        }
        return paddedBlock;
    }
 // сдвиг на один бит влево
    public static byte[] shifting(byte[] value) {
        BitSet startValue = BitSet.valueOf(value);

        for (int i = 0; i < value.length * byteSize; i++) {
            if (i != value.length * byteSize) {
                if (startValue.get(i + 1))
                    startValue.set(i);
                else startValue.clear(i);
            } else {
                if (startValue.get(0))
                    startValue.set(i);
                else startValue.clear(i);
            }
        }
        return startValue.toByteArray();
    }
}
