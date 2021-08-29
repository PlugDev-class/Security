package de.plugdev.openbusycloud.security;

import de.plugdev.openbusycloud.security.encryptions.Custom3DES;
import de.plugdev.openbusycloud.security.encryptions.CustomAES256;
import de.plugdev.openbusycloud.security.encryptions.CustomDES;
import de.plugdev.openbusycloud.security.encryptions.CustomRSA2048;
import lombok.Data;
import lombok.SneakyThrows;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

@Data
public class SecurityManager {

    private final ExecutorService executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);

    private final CustomAES256 aes256;
    private final CustomRSA2048 rsa2048;
    private final CustomDES des;
    private final Custom3DES three_des;

    private final String serverSignature;
    private final int iterations;

    @SneakyThrows
    public SecurityManager(int iterations, String serverSignature) {
        this.aes256 = new CustomAES256();
        this.rsa2048 = new CustomRSA2048();
        this.des = new CustomDES();
        this.three_des = new Custom3DES();

        this.iterations = iterations;
        this.serverSignature = serverSignature;
    }

    /* Encrypt a message by default AES256-Encryption */
    @SneakyThrows
    public byte[] secureMessage(String message) {
        message += (serverSignature);
        final byte[] firstByteArray = message.getBytes();
        final AtomicReference<byte[]> reference = new AtomicReference<>(firstByteArray);
        Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
        for (int iteration = 0; iteration < iterations; iteration++)
            reference.set(aes256.encrypt(reference.get()));
        return reference.get();
    }

    /* Decrypt a message by default AES256-Encryption */
    @SneakyThrows
    public String decryptMessage(byte[] message) {
        final AtomicReference<byte[]> reference = new AtomicReference<>(message);
        for (int iteration = 0; iteration < iterations; iteration++)
            reference.set(aes256.decrypt(reference.get()));

        String restString = new String(reference.get());
        String signature = restString.substring(restString.length() - serverSignature.length());
        if (!signature.equals(serverSignature)) {
            Logger.getLogger(getClass().getSimpleName()).severe("==========================================");
            Logger.getLogger(getClass().getSimpleName()).severe("Got String with an invalid signature!");
            Logger.getLogger(getClass().getSimpleName()).severe("Received signature: " + signature);
            Logger.getLogger(getClass().getSimpleName()).severe("==========================================");
            return null;
        }
        return new String(reference.get()).substring(0, restString.length() - serverSignature.length());
    }

}
