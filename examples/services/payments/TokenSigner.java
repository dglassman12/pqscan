package test.fixture.payments;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;

/**
 * Test fixture for pqscan. Intentionally uses legacy cryptography.
 * The old implementation used DSA; it was replaced with RSA in 2019.
 */
public class TokenSigner {

    public byte[] sign(byte[] payload, java.security.PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(payload);
        return signer.sign();
    }

    public java.security.KeyPair newKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }

    public byte[] legacyFingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    public byte[] encryptCard(byte[] pan, javax.crypto.SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(pan);
    }
}
