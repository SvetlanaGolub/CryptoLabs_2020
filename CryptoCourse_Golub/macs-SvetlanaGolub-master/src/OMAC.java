import org.apache.commons.codec.DecoderException;
import java.util.BitSet;

public class OMAC {

    private static AES aes = new AES();
    private static final int blockSize = 16;
    private static final String constantString = "10000111";
    private static final int base = 2;
    private static final int encryptMode = 1;
    private static final boolean padding = true;
    private static final boolean noPadding = false;
    private static final byte zero = 0x00;

    public static byte[] omacEncryptBlock(byte[] data, byte[] previousRes, byte[] key, boolean isFinalBlock) throws Exception {
        byte[] encryptBlock;
        byte[] xorResult;
        byte[] key1 = getKey1(key); // key For Full Block
        byte[] key2 = getKey2(key1); // key For Not Full Block
        aes.setCipher(encryptMode, key);
        if (isFinalBlock) {
            // если блок прследний, подксориваем ключ
            if (data.length == blockSize) {
                // если блок не требует дополнения, подксориваем первй ключ
                xorResult = Operations.xor(Operations.xor(previousRes, data), key1);
                encryptBlock = aes.AesBlockEncrypt(xorResult, Main.Mode.OMAC, noPadding);
            } else {
                // если блок необходимо дополнить, дополняем и ксорим со вторым ключом
                data = Operations.padding(data, Main.Mode.OMAC);
                xorResult = Operations.xor(Operations.xor(previousRes, data), key2);
                encryptBlock = aes.AesBlockEncrypt(xorResult, Main.Mode.OMAC, noPadding);
            }
        } else {
            // если блок не последний, ксорим с предидущим
            xorResult = Operations.xor(previousRes, data);
            encryptBlock = aes.AesBlockEncrypt(xorResult, Main.Mode.OMAC, noPadding);
        }
        return encryptBlock;
    }
// получаем первый ключ из данного ключа
    public static byte[] getKey1(byte[] key) throws Exception {
        byte[] zeroBytes = new byte[blockSize];
        byte[] constant = new byte[blockSize];
        // последний байт в константе не равен нулю
        constant[blockSize - 1] = (byte) Integer.parseInt(constantString, base);
        byte[] key1;
        aes.setCipher(encryptMode, key);
        //пропускаем нулевую строку через AES
        byte[] aesFromZero = aes.AesBlockEncrypt(zeroBytes, Main.Mode.OMAC, noPadding);
        BitSet bitSet = BitSet.valueOf(aesFromZero);
        // если первый бит равен нулю, сдвираем на один бит влево
        if (!bitSet.get(0))
            key1 = Operations.shifting(aesFromZero);
        else
        // если первый бит равен единице, после сдвига, ксорим с константой
            key1 = Operations.xor(Operations.shifting(aesFromZero), constant);
        return key1;
    }
// получаем второй ключ из первого ключа
    public static byte[] getKey2(byte[] key1) throws DecoderException {
        byte[] constant = new byte[blockSize];
        // последний байт в константе не равен нулю
        constant[blockSize - 1] = (byte) Integer.parseInt(constantString, base);
        byte[] key2;
        BitSet bitSet = BitSet.valueOf(key1);
        // если первый бит равен нулю, сдвираем на один бит влево
        if (!bitSet.get(0))
            key2 = Operations.shifting(key1);
        else
            // если первый бит равен единице, после сдвига, ксорим с константой
            key2 = Operations.xor(Operations.shifting(key1), constant);
        return key2;
    }

}
