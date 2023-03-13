package Encrypt;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class HKDF {
    public static byte[] getKey(byte[] key){
        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new GOST3411_2012_256Digest());
        hkdfBytesGenerator.init(HKDFParameters.defaultParameters(key));
        byte[] secretKey = new byte[32];
        hkdfBytesGenerator.generateBytes(secretKey, 0, 32);
        return secretKey;
    }
}
