package de.plugdev.openbusycloud;

import de.plugdev.openbusycloud.security.SecurityManager;
import lombok.Data;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.logging.Logger;

@Data
public class SecurityExample {

    public static void main(String[] args) {
        /* Sets the Loggerformat to custom-format */
        final Logger logger = Logger.getLogger(SecurityExample.class.getSimpleName());
        System.setProperty("java.util.logging.SimpleFormatter.format", "Security@Output: [%1$tT] %5$s%6$s%n");

        /* Declaring a message I want to encrypt/decrypt */
        final String message = "A message, not everyone should be able to read..";
        final SecurityManager securityManager = new SecurityManager(1, UUID.randomUUID().toString());

        /* Encryption/Decryption with AES256 */
        final byte[] encryptedAES256Array = securityManager.getAes256().encrypt(message.getBytes(StandardCharsets.UTF_8));
        final byte[] decryptedAES256Array = securityManager.getAes256().decrypt(encryptedAES256Array);

        /* Encryption/Decryption with RSA2048 */
        final byte[] encryptedRSA2048Array = securityManager.getRsa2048().encrypt(message.getBytes(StandardCharsets.UTF_8));
        final byte[] decryptedRSA2048Array = securityManager.getRsa2048().decrypt(encryptedRSA2048Array);

        /* Encryption/Decryption with DES */
        final byte[] encryptedDESArray = securityManager.getDes().encrypt(message.getBytes(StandardCharsets.UTF_8));
        final byte[] decryptedDESArray = securityManager.getDes().decrypt(encryptedDESArray);

        /* Encryption/Decryption with 3DES */
        final byte[] encrypted3DESArray = securityManager.getThree_des().encrypt(message.getBytes(StandardCharsets.UTF_8));
        final byte[] decrypted3DESArray = securityManager.getThree_des().decrypt(encrypted3DESArray);

        logger.info("Encrypted AES256: " + new String(encryptedAES256Array));
        logger.info("Decrypted AES256: " + new String(decryptedAES256Array));

        logger.info("Encrypted RSA2048: " + new String(encryptedRSA2048Array));
        logger.info("Decrypted RSA2048: " + new String(decryptedRSA2048Array));

        logger.info("Encrypted DES: " + new String(encryptedDESArray));
        logger.info("Decrypted DES: " + new String(decryptedDESArray));

        logger.info("Encrypted 3DES: " + new String(encrypted3DESArray));
        logger.info("Decrypted 3DES: " + new String(decrypted3DESArray));

    }
}
