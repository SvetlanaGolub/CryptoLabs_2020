import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDH {

    PrivateKey mySk;
    PublicKey myPk;
    PublicKey otherPk;
    private static final int keySize = 16;
    private static final String stdName = "secp256k1";
    private static final String keyGenAlgorithm = "EC";
    private static final String signAlgorithm = "SHA256withECDSA";
    private static final String secretAlgorithm = "ECDH";



    public byte[] getSecret() throws Exception {
        if (mySk == null || myPk == null || otherPk == null)
            throw new Exception("Define keys first");
        //берём экземпляр протокола согласования ключей
        KeyAgreement secret = KeyAgreement.getInstance(secretAlgorithm);
        //инициализируем его с помощью нашего закрытого ключа
        secret.init(mySk);
        //передаём открытый ключ другой стороны
        secret.doPhase(otherPk, true);
        return secret.generateSecret();
    }

    public void keyGen() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec params = new ECGenParameterSpec(stdName);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyGenAlgorithm);
        generator.initialize(params);
        KeyPair keyPair = generator.generateKeyPair();
        myPk = keyPair.getPublic();
        mySk = keyPair.getPrivate();
    }
}
