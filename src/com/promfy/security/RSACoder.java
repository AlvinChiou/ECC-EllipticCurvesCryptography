package com.promfy.security;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * RSA 
 �o�غ�k1978�~�N�X�{�F�A���O�Ĥ@�ӬJ��Ω�ƾڥ[�K�]��Ω�Ʀrñ�W����k�C������z�ѩM�ާ@�A�]�ܬy��C��k���W�r�H�o���̪��W�r�R�W�GRon Rivest, AdiShamir �MLeonard Adleman�C
 �o�إ[�K��k���S�I�D�n�O�K�_���ܤơA�W��ڭ̬ݨ�DES�u���@�ӱK�_�C�۷��u���@���_�͡A�p�G�o���_�ͥ�F�A�ƾڤ]�N���w���F�CRSA�P�ɦ�����_�͡A���_�P�p�_�C�P�ɤ���Ʀrñ�W�C�Ʀrñ�W���N�q�b��A��ǿ�L�Ӫ��ƾڶi�����C�T�O�ƾڦb�ǿ�u�{�����Q�ק�C

 �y�{���R�G
 �Ҥ�c�رK�_���A�N���_���G���A��A�N�p�_�O�d�C
 �Ҥ�ϥΨp�_�[�K�ƾڡA�M��Ψp�_��[�K�᪺�ƾ�ñ�W�A�o�e���A��ñ�W�H�Υ[�K�᪺�ƾڡF�A��ϥΤ��_�Bñ�W�����ҫݸѱK�ƾڬO�_���ġA�p�G���ĨϥΤ��_��ƾڸѱK�C
 �A��ϥΤ��_�[�K�ƾڡA�V�Ҥ�o�e�g�L�[�K�᪺�ƾڡF�Ҥ���o�[�K�ƾڡA�q�L�p�_�ѱK�C
 */
public abstract class RSACoder extends Coder {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * �Ψp�_��H���ͦ��Ʀrñ�W
     *
     * @param data       �[�K�ƾ�
     * @param privateKey �p�_
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // �ѱK��base64�s�X���p�_
        byte[] keyBytes = decryptBASE64(privateKey);

        // �c�yPKCS8EncodedKeySpec��H
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM ���w���[�K��k
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // ���p�_�͹�H
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // �Ψp�_��H���ͦ��Ʀrñ�W
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }

    /**
     * ����Ʀrñ�W
     *
     * @param data      �[�K�ƾ�
     * @param publicKey ���_
     * @param sign      �Ʀrñ�W
     * @return ���禨�\��^true ���Ѫ�^false
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {

        // �ѱK��base64�s�X�����_
        byte[] keyBytes = decryptBASE64(publicKey);

        // �c�yX509EncodedKeySpec��H
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM ���w���[�K��k
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // �����_�͹�H
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);

        // ����ñ�W�O�_���`
        return signature.verify(decryptBASE64(sign));
    }

    /**
     * �ѱK<br>
     * �Ψp�_�ѱK
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key)
            throws Exception {
        // ��K�_�ѱK
        byte[] keyBytes = decryptBASE64(key);

        // ���o�p�_
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // ��ƾڸѱK
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * �ѱK<br>
     * �Ψp�_�ѱK
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, String key)
            throws Exception {
        // ��K�_�ѱK
        byte[] keyBytes = decryptBASE64(key);

        // ���o���_
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // ��ƾڸѱK
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * �[�K<br>
     * �Τ��_�[�K
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String key)
            throws Exception {
        // �綠�_�ѱK
        byte[] keyBytes = decryptBASE64(key);

        // ���o���_
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // ��ƾڥ[�K
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * �[�K<br>
     * �Ψp�_�[�K
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key)
            throws Exception {
        // ��K�_�ѱK
        byte[] keyBytes = decryptBASE64(key);

        // ���o�p�_
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // ��ƾڥ[�K
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * ���o�p�_
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);

        return encryptBASE64(key.getEncoded());
    }

    /**
     * ���o���_
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);

        return encryptBASE64(key.getEncoded());
    }

    /**
     * ��l�ƱK�_
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator
                .getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        // ���_
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // �p�_
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }
}