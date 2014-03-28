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
 * DSA-Digital Signature Algorithm 是Schnorr和ElGamal?名算法的?种，被美?NIST作?DSS(DigitalSignature Standard)。??的?，?是一种更高?的??方式，用作?字?名。不??只有公?、私?，?有?字?名。私?加密生成?字?名，公????据及?名。如果?据和?名不匹配?????失?！?字?名的作用就是校??据在???程中不被修改。?字?名，是?向加密的升?！ 

 */
public abstract class DSACoder extends Coder {

    public static final String ALGORITHM = "DSA";

    /**
     * 默?密?字??
     *
     * <pre>
     * DSA
     * Default Keysize 1024
     * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive).
     * </pre>
     */
    private static final int KEY_SIZE = 1024;

    /**
     * 默?种子
     */
    private static final String DEFAULT_SEED = "0f22507a10bbddd07d8a3082122966e3";

    private static final String PUBLIC_KEY = "DSAPublicKey";
    private static final String PRIVATE_KEY = "DSAPrivateKey";

    /**
     * 用私??信息生成?字?名
     *
     * @param data
     *            加密?据
     * @param privateKey
     *            私?
     *
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // 解密由base64??的私?
        byte[] keyBytes = decryptBASE64(privateKey);

        // 构造PKCS8EncodedKeySpec?象
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

        // 取私?匙?象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 用私??信息生成?字?名
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }

    /**
     * 校??字?名
     *
     * @param data
     *            加密?据
     * @param publicKey
     *            公?
     * @param sign
     *            ?字?名
     *
     * @return 校?成功返回true 失?返回false
     * @throws Exception
     *
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {

        // 解密由base64??的公?
        byte[] keyBytes = decryptBASE64(publicKey);

        // 构造X509EncodedKeySpec?象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

        // 取公?匙?象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());
        signature.initVerify(pubKey);
        signature.update(data);

        // ???名是否正常
        return signature.verify(decryptBASE64(sign));
    }

    /**
     * 生成密?
     *
     * @param seed
     *            种子
     * @return 密??象
     * @throws Exception
     */
    public static Map<String, Object> initKey(String seed) throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);
        // 初始化?机?生器
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
     * 默?生成密?
     *
     * @return 密??象
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        return initKey(DEFAULT_SEED);
    }

    /**
     * 取得私?
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
     * 取得公?
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
