import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDSA {

    PrivateKey mySk;
    PublicKey myPk;
    PublicKey otherPk;
    private static final int keySize = 16;
    private static final String stdName = "secp256k1";
    private static final String keyGenAlgorithm = "EC";
    private static final String signAlgorithm = "SHA256withECDSA";

    //другая сторона проверяет подпись с помощью нашего публичного ключа
    public boolean ver(byte[] message, byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature verify = Signature.getInstance(signAlgorithm);
        verify.initVerify(otherPk);
        verify.update(message);
        return verify.verify(sign);
    }

    //подписываем сообщение с помощью своего секретного ключа
    public byte[] sign(byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signAlgorithm);
        signature.initSign(mySk);
        signature.update(message);
        return signature.sign();
    }

    public void keyGen() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec params = new ECGenParameterSpec(stdName);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyGenAlgorithm);
        generator.initialize(params);
        //генерируем пару ключей
        KeyPair keyPair = generator.generateKeyPair();
        myPk = keyPair.getPublic();
        mySk = keyPair.getPrivate();
    }
}
