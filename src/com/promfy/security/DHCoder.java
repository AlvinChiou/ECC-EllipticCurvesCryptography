package com.promfy.security;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 * DH
 Diffie-Hellman��k(D-H��k)�A�K?�@�P??�C�O�Ѥ�?�K?�K?�^�����HDiffie�MHellman�Ҵ��X���@����Q�C??��?�N�O��??�W��?�b��?�C�^�W��?�H���H�ͦ�"�@�P"���B�i�H�@�ɪ��K?�C?�y??�A�N�O�ѥҤ�?�X�@?�K?�]��?�B�p?�^�A�A��̷ӥҤ褽??�ͤA��K??�]��?�B�p?�^�C�H��?��?�A�@??�u??�O�K��?�A�P??��ϥΦP�@��??�[�K��k�۫إ��a�K?�]SecretKey�^??�u�[�K�C??�A�b���q�F���a�K?�]SecretKey�^��k�Z�A�ҤA?�褽?�ۤv����?�A�ϥ�?�誺��?�M?�~?�ͪ��p?�[�K?�u�A�P?�i�H�ϥ�?�誺��?�M�ۤv���p???�u�ѱK�C��??�O�ҤA?��?��A�i�H?�i?�h��@��?�u�q?�A??�N�����F�I?�椬?�u���w���q?�I?��k���_��?���P�E�w�z�X�X��???�w�z�C

 �y�{���R�G

 1.�Ҥ��۫رK??�I�A?��?����?�A��A?�p?�O�d�F?��?�w?�u�[�K��k�F�A��q?�Ҥ褽?�۫رK??�I�A?��?����?�Ҥ�A?�p?�O�d�C
 2.�Ҥ�ϥΨp?�B�A�褽?�B?�w?�u�[�K��k�۫إ��a�K?�A�M�Z�q?���a�K?�[�K?�u�A?�e?�A��[�K�Z��?�u�F�A��ϥΨp?�B�Ҥ褽?�B?�w?�u�[�K��k�۫إ��a�K?�A�M�Z�q?���a�K???�u�ѱK�C
 3.�A��ϥΨp?�B�Ҥ褽?�B?�w?�u�[�K��k�۫إ��a�K?�A�M�Z�q?���a�K?�[�K?�u�A?�e?�Ҥ�[�K�Z��?�u�F�Ҥ�ϥΨp?�B�A�褽?�B?�w?�u�[�K��k�۫إ��a�K?�A�M�Z�q?���a�K???�u�ѱK�C
 */

/**
 * DH�w��???��
 *
 * @author ��?
 * @version 1.0
 * @since 1.0
 */
public abstract class DHCoder extends Coder {
    public static final String ALGORITHM = "DH";

    /**
     * �q?�K?�r??
     *
     * <pre>
     * DH
     * Default Keysize 1024
     * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive).
     * </pre>
     */
    private static final int KEY_SIZE = 1024;

    /**
     * DH�[�K�U�ݭn�@��??�[�K��k??�u�[�K�A?����?�ϥ�DES�A�]�i�H�ϥΨ�L??�[�K��k�C
     */
    public static final String SECRET_ALGORITHM = "DES";
    private static final String PUBLIC_KEY = "DHPublicKey";
    private static final String PRIVATE_KEY = "DHPrivateKey";

    /**
     * ��l�ƥҤ�K?
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // �Ҥ褽?
        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();

        // �Ҥ�p?
        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * ��l�ƤA��K?
     *
     * @param key
     *            �Ҥ褽?
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey(String key) throws Exception {
        // �ѪR�Ҥ褽?
        byte[] keyBytes = decryptBASE64(key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        // �ѥҤ褽?�۫ؤA��K?
        DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(keyFactory.getAlgorithm());
        keyPairGenerator.initialize(dhParamSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // �A�褽?
        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();

        // �A��p?
        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);

        return keyMap;
    }

    /**
     * �[�K<br>
     *
     * @param data
     *            �ݥ[�K?�u
     * @param publicKey
     *            �Ҥ褽?
     * @param privateKey
     *            �A��p?
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, String publicKey,
                                 String privateKey) throws Exception {

        // �ͦ����a�K?
        SecretKey secretKey = getSecretKey(publicKey, privateKey);

        // ?�u�[�K
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    /**
     * �ѱK<br>
     *
     * @param data
     *            �ݸѱK?�u
     * @param publicKey
     *            �A�褽?
     * @param privateKey
     *            �A��p?
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String publicKey,
                                 String privateKey) throws Exception {

        // �ͦ����a�K?
        SecretKey secretKey = getSecretKey(publicKey, privateKey);
        // ?�u�ѱK
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    /**
     * �۫رK?
     *
     * @param publicKey
     *            ��?
     * @param privateKey
     *            �p?
     * @return
     * @throws Exception
     */
    private static SecretKey getSecretKey(String publicKey, String privateKey)
            throws Exception {
        // ��l�Ƥ�?
        byte[] pubKeyBytes = decryptBASE64(publicKey);

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        // ��l�ƨp?
        byte[] priKeyBytes = decryptBASE64(privateKey);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
        Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory
                .getAlgorithm());
        keyAgree.init(priKey);
        keyAgree.doPhase(pubKey, true);

        // �ͦ����a�K?
        SecretKey secretKey = keyAgree.generateSecret(SECRET_ALGORITHM);

        return secretKey;
    }

    /**
     * ���o�p?
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
     * ���o��?
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
}
