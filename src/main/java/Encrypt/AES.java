package Encrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class AES {
    public static Key generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        return keyGenerator.generateKey();
    }
    public static byte[] encrypt(byte[] key, byte[] data) throws Exception{

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] out = cipher.doFinal(data);
        return out;

    }

    public static byte[] decrypt(byte[] key, byte[] data) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] out = cipher.doFinal(data);
        return out;


    }
}
