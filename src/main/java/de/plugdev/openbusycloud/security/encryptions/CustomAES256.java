package de.plugdev.openbusycloud.security.encryptions;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;

public class CustomAES256 implements Encryption {

    private final SecretKey secretKey;

    @SneakyThrows
    public CustomAES256() {
        final KeyGenerator aesKeyGenerator = KeyGenerator.getInstance(getCipherAlgorithm());
        aesKeyGenerator.init(256);
        secretKey = aesKeyGenerator.generateKey();
    }

    @SneakyThrows
    @Override
    public byte[] encrypt(byte[] message) {
        final Cipher aesCipher = Cipher.getInstance(getCipherAlgorithm());
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return aesCipher.doFinal(message);
    }

    @SneakyThrows
    @Override
    public byte[] decrypt(byte[] message) {
        final Cipher aesCipher = Cipher.getInstance(getCipherAlgorithm());
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        return aesCipher.doFinal(message);
    }

    @Override
    public String getCipherAlgorithm() {
        return "AES";
    }

    @Override
    public String getEncoding() {
        return null;
    }

    @Override
    public Key[] getKeys() {
        return new Key[] { secretKey };
    }
}
