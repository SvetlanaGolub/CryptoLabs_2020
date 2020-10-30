import org.apache.commons.codec.binary.Hex;

import java.io.FileWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {

    private static final String charset ="UTF-8";
    private static final String file_path = "D:\\MyDoc\\Desktop\\crypt\\sigma-ec-SvetlanaGolub\\src\\results\\Result";

    public static void main(String[] args) throws Exception {
        FileWriter writer = new FileWriter(file_path, true);
        writer.write("\t" + "Checking signs and macs:" + "\n\n");

        String AliceName = "Sigma identifier for Alice";
        String BobName = "Sigma identifier for Bob";
        Sigma Alice = new Sigma(AliceName);
        Sigma Bob = new Sigma(BobName);
        //предварительный обмен ключами
        Alice.keyExchange(Bob);
        Bob.keyExchange(Alice);
        //первый этап
        //Алиса передаёт Бобу открытый ключ
        Alice.firstStep(Bob);
        //второй этап
        //Боб передаёт Алисе открытый ключ, подпись и мак
        Bob.secondStep(Alice);
        //Алиса проверяет подписи от Боба
        //и передаёт ему подпись и мак
        Alice.thirdStep(Bob);
        //Боб проверяет подпись и мак от Алисы
        //если проверки будут не пройдены, следующие две функции выбросят исключения
        Bob.checking();
        //если проверки пройдены, мы запишем это в файл
        writer.write("- Signatures are valid" + "\n" + "- Authentications passed" + "\n\n");
        //В итоге мы получили общий секрет
        //С его помощью получили ключи для мака и для шифрования

        //Шифруем сообщение
        writer.write("\t" + "Checking encryption:" + "\n\n");
        String message = "Some words to encrypt and then decrypt with keys from asymmetric cryptography";
        writer.write("Message to encrypt:  " + message + "\n");
        //Алиса шифрует сообщение и вычисляет мак
        byte[] cipherText = AES.encrypt(message.getBytes(charset), Alice.k_encrypt);
        byte[] mac = AES.getMac(cipherText, Alice.k_mac);
        //Боб проверяет мак и расшифровывает сообщение
        AES.checkMac(mac, cipherText, Bob.k_mac);
        byte[] plainText = AES.decrypt(cipherText, Bob.k_encrypt);
        writer.write("Decrypted message:  " + new String(plainText));
        writer.flush();
        writer.close();

    }

}
