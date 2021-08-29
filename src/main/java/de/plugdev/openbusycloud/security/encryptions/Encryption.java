package de.plugdev.openbusycloud.security.encryptions;

import java.security.Key;

public interface Encryption {

    byte[] encrypt(byte[] message);
    byte[] decrypt(byte[] byteArray);

    String getCipherAlgorithm();
    String getEncoding();
    Key[] getKeys();

}
