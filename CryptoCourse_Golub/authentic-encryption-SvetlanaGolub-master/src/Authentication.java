import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Authentication {

    private byte[] key;
    private int mode;
    private Cipher cipher;
    private byte[] result;
    private static final String algorithm = "AES";
    private static final String cipherMode = "AES/CTR/NoPadding";
    private static final int blockSize = 16;
    private static final int encryptMode = 1;
    private static final int decryptMode = 2;
    private static final int hmacSize = 32;
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\authentic-encryption-SvetlanaGolub\\src\\results\\Result";


    Authentication(int mode) {
        this.mode = mode;
    }

    //задаём ключ и сразу определяем объект шифра
    public void SetKey(byte[] key) throws Exception {
        if (key.length != blockSize)
            throw new Exception("wrong key size");
        this.key = key;
        SecretKey aesKey = new SecretKeySpec(key, algorithm);
        this.cipher = Cipher.getInstance(cipherMode);
        cipher.init(mode, aesKey, new IvParameterSpec(key));
    }

    byte[] ProcessData(byte[] data) throws Exception {
        byte[] hmac = null;
        int blockStart = 0;
        int blockEnd = blockSize;
        boolean isFinal = false;
        switch (mode) {
            case (encryptMode):
                //пооучаем iv из ключа
                byte[] iv = new IvParameterSpec(key).getIV();
                //помешаем его в начало нашего результата
                addToResult(iv);
                int count = (int) Math.ceil((double) data.length / blockSize);
                for (int i = 0; i < count; i++) {
                    if (blockEnd >= data.length) {
                        blockEnd = data.length;
                        isFinal = true;
                    }
                    byte[] block = Arrays.copyOfRange(data, blockStart, blockEnd);
                    //если блок не финальный, то hmac будет null
                    hmac = AddBlock(block, isFinal);
                    blockStart = blockEnd;
                    blockEnd += blockSize;
                }
                //если hmac остался рвным null, то произошла ошибка
                assert hmac != null;
                break;

            case (decryptMode):
                //выделяем шифртекст, от которого будем брать hmac
                byte[] cipherText = Arrays.copyOfRange(data, 0, data.length - hmacSize);
                //выделяем из всех данных зашифрованные
                byte[] encryptedData = Arrays.copyOfRange(data, blockSize, data.length - hmacSize);
                //выделяем hmac как последние 32 байта данных
                hmac = Arrays.copyOfRange(data, data.length - hmacSize, data.length);
                //высчитываем hmac для проверки
                byte[] checkHmac = HMAC.getHMAC(cipherText, key);
                //сравниваем и выводим результат
                FileWriter writer = new FileWriter(file_path, true);
                boolean check = Arrays.equals(checkHmac, hmac);
                writer.write("Authentication passed? " + "\t\t" + check + '\n');
                writer.flush();
                //если hmac не равны, то выдаём ошибку
                if (!check)
                    throw new Exception("Authentication failed");
                count = (int) Math.ceil((double) encryptedData.length / blockSize);
                blockStart = 0;
                blockEnd = blockSize;
                for (int i = 0; i < count; i++) {
                    if (blockEnd > data.length) {
                        blockEnd = data.length;
                        isFinal = true;
                    }
                    byte[] block = Arrays.copyOfRange(encryptedData, blockStart, blockEnd);
                    AddBlock(block, isFinal);
                    blockStart = blockEnd;
                    blockEnd += blockSize;
                }
                break;
            default:
                throw new Exception("No such method");
        }
        return result;
    }

    public byte[] AddBlock(byte[] dataBlock, boolean isFinal) throws BadPaddingException, IllegalBlockSizeException, IOException, InvalidKeyException, NoSuchAlgorithmException {
        //добавляем следующий блок к результату
        byte[] hmac = null;
        if (isFinal) {
            addToResult(cipher.doFinal(dataBlock));
            //высчитываем hmac от iv и шифртекста
            hmac = HMAC.getHMAC(result, key);
            addToResult(hmac);
        } else {
            addToResult(cipher.update(dataBlock));
        }
        return hmac;
    }

    public void addToResult(byte[] block) throws IOException {
        //конкатинируем результат со следующим блоком
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(result);
        b.write(block);
        result = b.toByteArray();
        b.reset();
    }

    public void reset(){
        key = null;
        result=null;
    }

}


/*
        if(result == null) {
                result = block;
                return;
                }
                byte[] newResult = new byte[result.length + block.length];
                System.arraycopy(result, 0, newResult, 0, result.length);
                System.arraycopy(block, 0, newResult, result.length, block.length);
                result = newResult;*/
