package Encrypt;

import org.bouncycastle.crypto.generators.GOST3410KeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import java.security.*;

public class Digest {
    public static KeyPair generateKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("GOST3410", "BC");
        return keyPairGenerator.generateKeyPair();
    }
    public static byte[] signData(byte[] data, Key prKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Signature signature = Signature.getInstance("GOST3410", "BC");
        signature.initSign((PrivateKey) prKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean checkSign(byte[] sign, byte[] data, Key prKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Signature signature = Signature.getInstance("GOST3410", "BC");
        signature.initVerify((PublicKey) prKey);
        signature.update(data);
        return signature.verify(sign);
    }
}
