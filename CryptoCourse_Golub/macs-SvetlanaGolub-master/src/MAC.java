import java.util.Arrays;

public class MAC {

    private byte[] key;
    private byte[] currentResult;
    private Main.Mode mode;
    private byte[] previousBlock = null;
    private boolean itIsFinal = false;
    private byte[] tag;

    private static final boolean finalBlock = true;
    private static final int truncateSize = 8;
    private static final int blockSize = 16;

    public MAC(Main.Mode mode) {
        this.mode = mode;
    }

    public void SetKey(byte[] key) {
        this.key = key;
    }

    public byte[] ComputeMac(byte[] data) throws Exception {
        // высчитываем количество блоков
        int count = (int) Math.ceil((double) data.length / blockSize);
        int start = 0;
        int end = blockSize;
        for (int i = 0; i < count; i++) {
            byte[] dataBlock = Arrays.copyOfRange(data, start, end);
            MacAddBlock(dataBlock);
            start = end;
            end = start + blockSize;
            if (end > data.length)
                end = data.length;
            if (itIsFinal)
                break;
        }
        MacFinalize();
        return tag;
    }

    public boolean VerifyMac(byte[] data, byte[] tag) throws Exception {
        byte[] tagToCompare = ComputeMac(data);
        return Arrays.equals(tag, tagToCompare);
    }

    public void MacFinalize() throws Exception {
        if (currentResult == null) {
            throw new Exception("Nothing to finalize");
        }
        switch (mode) {
            case OMAC:
                // шифруем последний блок, подксоривая к нему специальные ключи
                tag = OMAC.omacEncryptBlock(previousBlock, currentResult, key, finalBlock);
                break;
            case tMAC:
                // усекаем полученный результат
                tag = Arrays.copyOf(currentResult, truncateSize);
                break;
            case HMAC:
                // хэшируем последний блок, сконкатинированный с
                byte[] key2 = HMAC.getFinalKey(HMAC.getKey2(key));
                tag = HMAC.hmacEncryptBlock(currentResult, key2);
                break;
            default:
                throw new Exception("encryption mode mode" + mode + "is not supported");

        }
    }

    public void MacAddBlock(byte[] dataBlock) throws Exception {
        // если блок неполный автоматически считаем его последним
        if (dataBlock.length < blockSize)
            itIsFinal = true;
        switch (mode) {
            case OMAC:
                // если это первый блок, запоминаем его и не делаем никаких операций
                if (currentResult == null) {
                    currentResult = new byte[blockSize];
                    previousBlock = Arrays.copyOf(dataBlock, dataBlock.length);
                    break;
                }
                // иначе шифруем предыдущий блок
                this.currentResult = OMAC.omacEncryptBlock(previousBlock, currentResult, key, itIsFinal);
                previousBlock = Arrays.copyOf(dataBlock, dataBlock.length);
                break;
            case tMAC:
                if (currentResult == null) {
                    currentResult = new byte[blockSize];
                }
                // шифруем блоки по алгоритму CBC
                this.currentResult = tMAC.trMacEncryptBlock(dataBlock, currentResult, key, itIsFinal);
                break;
            case HMAC:
                // если блок первый, высчитываем ключ,
                // с которым будем его конкатинировать перед хэшированием
                if (currentResult == null)
                    currentResult = HMAC.getFinalKey(HMAC.getKey1(key));
                // иначе конкатинируем с прошлым результатом
                this.currentResult = HMAC.hmacEncryptBlock(dataBlock, currentResult);
                break;
            default:
                throw new Exception("encryption mode mode" + mode + "is not supported");
        }
    }

    public void resetMac(){
        previousBlock = null;
        itIsFinal = false;
        currentResult = null;
    }


}
