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
 這種算法1978年就出現了，它是第一個既能用於數據加密也能用於數字簽名的算法。它易於理解和操作，也很流行。算法的名字以發明者的名字命名：Ron Rivest, AdiShamir 和Leonard Adleman。
 這種加密算法的特點主要是密鑰的變化，上文我們看到DES只有一個密鑰。相當於只有一把鑰匙，如果這把鑰匙丟了，數據也就不安全了。RSA同時有兩把鑰匙，公鑰與私鑰。同時支持數字簽名。數字簽名的意義在於，對傳輸過來的數據進行校驗。確保數據在傳輸工程中不被修改。

 流程分析：
 甲方構建密鑰對兒，將公鑰公佈給乙方，將私鑰保留。
 甲方使用私鑰加密數據，然後用私鑰對加密後的數據簽名，發送給乙方簽名以及加密後的數據；乙方使用公鑰、簽名來驗證待解密數據是否有效，如果有效使用公鑰對數據解密。
 乙方使用公鑰加密數據，向甲方發送經過加密後的數據；甲方獲得加密數據，通過私鑰解密。
 */
public abstract class RSACoder extends Coder {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * 用私鑰對信息生成數字簽名
     *
     * @param data       加密數據
     * @param privateKey 私鑰
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // 解密由base64編碼的私鑰
        byte[] keyBytes = decryptBASE64(privateKey);

        // 構造PKCS8EncodedKeySpec對象
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 取私鑰匙對象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 用私鑰對信息生成數字簽名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }

    /**
     * 校驗數字簽名
     *
     * @param data      加密數據
     * @param publicKey 公鑰
     * @param sign      數字簽名
     * @return 校驗成功返回true 失敗返回false
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {

        // 解密由base64編碼的公鑰
        byte[] keyBytes = decryptBASE64(publicKey);

        // 構造X509EncodedKeySpec對象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 取公鑰匙對象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);

        // 驗證簽名是否正常
        return signature.verify(decryptBASE64(sign));
    }

    /**
     * 解密<br>
     * 用私鑰解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key)
            throws Exception {
        // 對密鑰解密
        byte[] keyBytes = decryptBASE64(key);

        // 取得私鑰
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 對數據解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 解密<br>
     * 用私鑰解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, String key)
            throws Exception {
        // 對密鑰解密
        byte[] keyBytes = decryptBASE64(key);

        // 取得公鑰
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 對數據解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * 加密<br>
     * 用公鑰加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String key)
            throws Exception {
        // 對公鑰解密
        byte[] keyBytes = decryptBASE64(key);

        // 取得公鑰
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 對數據加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * 加密<br>
     * 用私鑰加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key)
            throws Exception {
        // 對密鑰解密
        byte[] keyBytes = decryptBASE64(key);

        // 取得私鑰
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 對數據加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 取得私鑰
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
     * 取得公鑰
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
     * 初始化密鑰
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator
                .getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        // 公鑰
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // 私鑰
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }
}