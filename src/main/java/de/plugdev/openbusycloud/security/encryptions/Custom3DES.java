package de.plugdev.openbusycloud.security.encryptions;

import java.security.Key;

public class Custom3DES extends CustomDES {

    @Override
    public byte[] encrypt(byte[] message) {
        return super.encrypt(super.encrypt(super.encrypt(message)));
    }

    @Override
    public byte[] decrypt(byte[] message) {
        return super.decrypt(super.decrypt(super.decrypt(message)));
    }

    @Override
    public String getCipherAlgorithm() {
        return super.getCipherAlgorithm();
    }

    @Override
    public String getEncoding() {
        return super.getEncoding();
    }

    @Override
    public Key[] getKeys() {
        return super.getKeys();
    }

}
