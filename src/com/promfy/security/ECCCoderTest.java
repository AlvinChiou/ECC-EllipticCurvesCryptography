package com.promfy.security;

import static org.junit.Assert.*;
import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Map;

import org.junit.Test;

public class ECCCoderTest {

    @Test
    public static void main(String[] args) throws Exception {
        String inputStr = "abc";
        byte[] data = inputStr.getBytes();

        Map<String, Object> keyMap = ECCCoder.initKey();

        String publicKey = ECCCoder.getPublicKey(keyMap);
        String privateKey = ECCCoder.getPrivateKey(keyMap);
        System.err.println("公鑰: \n" + publicKey);
        System.err.println("私鑰： \n" + privateKey);

        byte[] encodedData = ECCCoder.encrypt(data, publicKey);

        byte[] decodedData = ECCCoder.decrypt(encodedData, privateKey);

        String outputStr = new String(decodedData);
        System.err.println("加密前: " + inputStr + "\n\r" + "解密後: " + outputStr);
        assertEquals(inputStr, outputStr);
    }
}

