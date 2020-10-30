import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Sigma {

    byte[] id;
    byte[] otherId;
    ECDSA ecdsa = new ECDSA();
    ECDH ecdh = new ECDH();
    byte[] r_A = new byte[rSize];
    byte[] r_B = new byte[rSize];
    byte[] k_mac;
    byte[] k_encrypt;
    byte[] otherSign;
    byte[] otherMac;
    private static final int keySize = 16;
    private static final int rSize = 128;
    private static final String algorithm = "HmacSHA256";
    private static final String charset ="UTF-8";

    Sigma(String name) throws UnsupportedEncodingException {
        this.id = name.getBytes(charset);
    }

    public void keyExchange(Sigma otherPerson) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ecdsa.keyGen();
        otherPerson.ecdsa.otherPk = ecdsa.myPk;
    }

    public void firstStep(Sigma Bob) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ecdh.keyGen();
        SecureRandom.getInstanceStrong().nextBytes(r_A);
        Bob.ecdh.otherPk = ecdh.myPk;
        Bob.r_A = r_A;
    }

    public void secondStep(Sigma Alice) throws Exception {
        //генирируем эфимерные ключи
        ecdh.keyGen();
        //генирируем произвольную последовательность r
        SecureRandom.getInstanceStrong().nextBytes(r_B);
        //определяем общий секрет и берём от него prf, чтобы получить ключи
        prf();
        //вычисляем мак от своего идентификатора и передаём его собеседнику
        Alice.otherMac = getMac(id);
        byte[] publicKeys = concat(ecdh.otherPk.getEncoded(), ecdh.myPk.getEncoded());
        //вычисляем подпись и передаём собеседнику
        Alice.otherSign = ecdsa.sign(publicKeys);
        //передаём свой открытый ключ
        Alice.ecdh.otherPk = ecdh.myPk;
        //передаём идентификатор
        Alice.otherId = id;
        Alice.r_B = r_B;
    }

    public void thirdStep(Sigma Bob) throws Exception {
        //проверяем подпись
        checkSign();
        //получаем ключи с помощью общего секрета
        prf();
        //проверяем мак от идентификатора собеседника
        checkMac(otherId);
        //передаём мак
        Bob.otherMac = getMac(id);
        byte[] publicKeys = concat(ecdh.otherPk.getEncoded(), ecdh.myPk.getEncoded());
        //передаём подпись
        Bob.otherSign = ecdsa.sign(publicKeys);
        //передаём идентификатор
        Bob.otherId = id;
    }

    public void prf() throws Exception {
        if (r_A == null || r_B == null)
            throw new Exception("Define r_A and r_B first");
        Mac prf = Mac.getInstance(algorithm);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(r_A);
        b.write(r_B);
        byte[] key = b.toByteArray();
        b.reset();
        SecretKeySpec prfKey = new SecretKeySpec(key, algorithm);
        prf.init(prfKey);
        //берём prf от общего секрета
        byte[] prfResult = prf.doFinal(ecdh.getSecret());
        k_mac = Arrays.copyOf(prfResult, prfResult.length / 2);
        k_encrypt = Arrays.copyOfRange(prfResult, prfResult.length / 2, prfResult.length);
    }

    public byte[] getMac(byte[] anyId) throws Exception {
        if (k_mac == null)
            throw new Exception("Define key for mac first");
        Mac mac = Mac.getInstance(algorithm);
        SecretKeySpec macKey = new SecretKeySpec(k_mac, algorithm);
        mac.init(macKey);
        //берём мак от нашего идентификатора
        return mac.doFinal(anyId);
    }

    public void checking() throws Exception {
        //если проверки будут не пройдены, эти функция выбросят исключения
        checkMac(otherId);
        checkSign();
    }

    public void checkMac(byte[] checkId) throws Exception {
        boolean check = Arrays.equals(getMac(checkId), otherMac);
        if (!check)
            throw new Exception("Wrong mac. Authentication failed!");
    }

    public void checkSign() throws Exception {
        byte[] publicKeys = concat(ecdh.myPk.getEncoded(), ecdh.otherPk.getEncoded());
        //проверяем подпись, которую мы получили от собеседника
        boolean check = ecdsa.ver(publicKeys, otherSign);
        if (!check)
            throw new Exception("Wrong sign!");
    }

    public static byte[] concat(byte[] first, byte[] second) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(first);
        b.write(second);
        return b.toByteArray();
    }


}
