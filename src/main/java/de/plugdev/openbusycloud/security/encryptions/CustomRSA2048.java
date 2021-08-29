package de.plugdev.openbusycloud.security.encryptions;

import lombok.Data;
import lombok.SneakyThrows;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

@Data
public class CustomRSA2048 implements Encryption {

    private final KeyPair keyPair;

    @SneakyThrows
    public CustomRSA2048() {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        this.keyPair = keyPairGenerator.generateKeyPair();
    }

    @SneakyThrows
    public byte[] encrypt(byte[] message) {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(message);
    }

    @SneakyThrows
    public byte[] decrypt(byte[] message) {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        return cipher.doFinal(message);
    }

    @Override
    public String getCipherAlgorithm() {
        return "RSA";
    }

    @Override
    public String getEncoding() {
        return null;
    }

    @Override
    public Key[] getKeys() {
        return new Key[] { keyPair.getPublic(), keyPair.getPrivate() };
    }
}
