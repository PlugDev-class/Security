package de.plugdev.openbusycloud.security.encryptions;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class CustomDES implements Encryption {

    private final SecretKey secretKey;
    private final byte[] iv = { 11, 22, 33, 44, 99, 88, 77, 66 };

    @SneakyThrows
    public CustomDES() {
        secretKey = KeyGenerator.getInstance(getCipherAlgorithm().substring(0, 3)).generateKey();
    }

    @SneakyThrows
    @Override
    public byte[] encrypt(byte[] message) {
        Cipher cipher = Cipher.getInstance(getCipherAlgorithm());
        AlgorithmParameterSpec parameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        return cipher.doFinal(message);
    }

    @SneakyThrows
    @Override
    public byte[] decrypt(byte[] message) {
        Cipher cipher = Cipher.getInstance(getCipherAlgorithm());
        AlgorithmParameterSpec parameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        return cipher.doFinal(message);
    }

    @Override
    public String getCipherAlgorithm() {
        return "DES/CBC/PKCS5Padding";
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
