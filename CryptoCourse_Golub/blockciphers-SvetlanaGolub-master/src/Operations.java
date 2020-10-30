import java.util.Arrays;

public class Operations {

    private static final int blockSize = 16;

    public static byte[] xor(byte[] firstValue, byte[] secondValue){
        int resultSize = Math.min(firstValue.length, secondValue.length);
        byte[] xorValue = new byte[resultSize];
        for (int i = 0; i < resultSize; i++) {
            xorValue[i] = (byte) (firstValue[i] ^ secondValue[i]);
        }
        return xorValue;
    }
//дополняем недостоющие байты в последнем блоке
    public static byte[] padding(byte[] block) {
        int extra = blockSize - block.length;
        byte[] paddedBlock = Arrays.copyOf(block, blockSize);
        for (int i = 0; i < extra; i++) {
            paddedBlock[blockSize - 1 - i] = (byte) extra;
        }
        return paddedBlock;
    }
//убираем лишние байты из последнего блока
    public static byte[] nopadding(byte[] block) {
        boolean isPadded = true;
        int extra = Math.abs(block[blockSize - 1]);
        for (int i = 0; i < extra; i++) {
            isPadded = block[blockSize - 1 - i] == extra;
            if (!isPadded) break;
        }
        if (isPadded)
            block = Arrays.copyOf(block, blockSize - extra);
        return block;
    }
}
