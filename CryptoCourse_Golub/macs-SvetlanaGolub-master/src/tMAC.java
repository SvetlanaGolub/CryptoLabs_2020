public class tMAC {

    private static final int encryptMode = 1;


    public static byte[] trMacEncryptBlock(byte[] data, byte[] forXor, byte[] key, boolean isFinalBlock) throws Exception {
        AES aes = new AES();
        aes.setCipher(encryptMode, key);
        byte[] xor = Operations.xor(data, forXor);
        return aes.AesBlockEncrypt(xor, Main.Mode.tMAC, isFinalBlock);
    }


}
