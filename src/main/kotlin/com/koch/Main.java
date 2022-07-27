package com.koch;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import com.ncipher.provider.km.nCipherKM;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
        System.setProperty("com.ncipher.provider.enable", "KeyFactory.ECDSA");
        Security.addProvider(new nCipherKM());
        KeyFactory.getInstance("ECDSA", MyBenchmark.PROVIDER);
    }
}
