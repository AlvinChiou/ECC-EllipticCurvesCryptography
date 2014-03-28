package com.promfy.security;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
/**
 * DSA-Digital Signature Algorithm �OSchnorr�MElGamal?�W��k��?���A�Q��?NIST�@?DSS(DigitalSignature Standard)�C??��?�A?�O�@����?��??�覡�A�Χ@?�r?�W�C��??�u����?�B�p?�A?��?�r?�W�C�p?�[�K�ͦ�?�r?�W�A��????�u��?�W�C�p�G?�u�M?�W���ǰt?????��?�I?�r?�W���@�δN�O��??�u�b???�{�����Q�ק�C?�r?�W�A�O?�V�[�K����?�I 

 */
public abstract class DSACoder extends Coder {

    public static final String ALGORITHM = "DSA";

    /**
     * �q?�K?�r??
     *
     * <pre>
     * DSA
     * Default Keysize 1024
     * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive).
     * </pre>
     */
    private static final int KEY_SIZE = 1024;

    /**
     * �q?���l
     */
    private static final String DEFAULT_SEED = "0f22507a10bbddd07d8a3082122966e3";

    private static final String PUBLIC_KEY = "DSAPublicKey";
    private static final String PRIVATE_KEY = "DSAPrivateKey";

    /**
     * �Ψp??�H���ͦ�?�r?�W
     *
     * @param data
     *            �[�K?�u
     * @param privateKey
     *            �p?
     *
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // �ѱK��base64??���p?
        byte[] keyBytes = decryptBASE64(privateKey);

        // �۳yPKCS8EncodedKeySpec?�H
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM ���w���[�K��k
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

        // ���p?��?�H
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // �Ψp??�H���ͦ�?�r?�W
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }

    /**
     * ��??�r?�W
     *
     * @param data
     *            �[�K?�u
     * @param publicKey
     *            ��?
     * @param sign
     *            ?�r?�W
     *
     * @return ��?���\��^true ��?��^false
     * @throws Exception
     *
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {

        // �ѱK��base64??����?
        byte[] keyBytes = decryptBASE64(publicKey);

        // �۳yX509EncodedKeySpec?�H
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // ALGORITHM ���w���[�K��k
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

        // ����?��?�H
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());
        signature.initVerify(pubKey);
        signature.update(data);

        // ???�W�O�_���`
        return signature.verify(decryptBASE64(sign));
    }

    /**
     * �ͦ��K?
     *
     * @param seed
     *            ���l
     * @return �K??�H
     * @throws Exception
     */
    public static Map<String, Object> initKey(String seed) throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);
        // ��l��?��?�;�
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(seed.getBytes());
        keygen.initialize(KEY_SIZE, secureRandom);

        KeyPair keys = keygen.genKeyPair();

        DSAPublicKey publicKey = (DSAPublicKey) keys.getPublic();
        DSAPrivateKey privateKey = (DSAPrivateKey) keys.getPrivate();

        Map<String, Object> map = new HashMap<String, Object>(2);
        map.put(PUBLIC_KEY, publicKey);
        map.put(PRIVATE_KEY, privateKey);

        return map;
    }

    /**
     * �q?�ͦ��K?
     *
     * @return �K??�H
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        return initKey(DEFAULT_SEED);
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
