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
 Diffie-Hellman算法(D-H算法)，密?一致??。是由公?密?密?体制的奠基人Diffie和Hellman所提出的一种思想。??的?就是允??名用?在公?媒体上交?信息以生成"一致"的、可以共享的密?。?句??，就是由甲方?出一?密?（公?、私?），乙方依照甲方公??生乙方密??（公?、私?）。以此?基?，作??据??保密基?，同??方使用同一种??加密算法构建本地密?（SecretKey）??据加密。??，在互通了本地密?（SecretKey）算法后，甲乙?方公?自己的公?，使用?方的公?和?才?生的私?加密?据，同?可以使用?方的公?和自己的私???据解密。不??是甲乙?方?方，可以?展?多方共享?据通?，??就完成了网?交互?据的安全通?！?算法源于中?的同余定理——中???定理。

 流程分析：

 1.甲方构建密??儿，?公?公布?乙方，?私?保留；?方?定?据加密算法；乙方通?甲方公?构建密??儿，?公?公布?甲方，?私?保留。
 2.甲方使用私?、乙方公?、?定?据加密算法构建本地密?，然后通?本地密?加密?据，?送?乙方加密后的?据；乙方使用私?、甲方公?、?定?据加密算法构建本地密?，然后通?本地密???据解密。
 3.乙方使用私?、甲方公?、?定?据加密算法构建本地密?，然后通?本地密?加密?据，?送?甲方加密后的?据；甲方使用私?、乙方公?、?定?据加密算法构建本地密?，然后通?本地密???据解密。
 */

/**
 * DH安全???件
 *
 * @author 梁?
 * @version 1.0
 * @since 1.0
 */
public abstract class DHCoder extends Coder {
    public static final String ALGORITHM = "DH";

    /**
     * 默?密?字??
     *
     * <pre>
     * DH
     * Default Keysize 1024
     * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive).
     * </pre>
     */
    private static final int KEY_SIZE = 1024;

    /**
     * DH加密下需要一种??加密算法??据加密，?里我?使用DES，也可以使用其他??加密算法。
     */
    public static final String SECRET_ALGORITHM = "DES";
    private static final String PUBLIC_KEY = "DHPublicKey";
    private static final String PRIVATE_KEY = "DHPrivateKey";

    /**
     * 初始化甲方密?
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 甲方公?
        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();

        // 甲方私?
        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * 初始化乙方密?
     *
     * @param key
     *            甲方公?
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey(String key) throws Exception {
        // 解析甲方公?
        byte[] keyBytes = decryptBASE64(key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        // 由甲方公?构建乙方密?
        DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(keyFactory.getAlgorithm());
        keyPairGenerator.initialize(dhParamSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 乙方公?
        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();

        // 乙方私?
        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);

        return keyMap;
    }

    /**
     * 加密<br>
     *
     * @param data
     *            待加密?据
     * @param publicKey
     *            甲方公?
     * @param privateKey
     *            乙方私?
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, String publicKey,
                                 String privateKey) throws Exception {

        // 生成本地密?
        SecretKey secretKey = getSecretKey(publicKey, privateKey);

        // ?据加密
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    /**
     * 解密<br>
     *
     * @param data
     *            待解密?据
     * @param publicKey
     *            乙方公?
     * @param privateKey
     *            乙方私?
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String publicKey,
                                 String privateKey) throws Exception {

        // 生成本地密?
        SecretKey secretKey = getSecretKey(publicKey, privateKey);
        // ?据解密
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    /**
     * 构建密?
     *
     * @param publicKey
     *            公?
     * @param privateKey
     *            私?
     * @return
     * @throws Exception
     */
    private static SecretKey getSecretKey(String publicKey, String privateKey)
            throws Exception {
        // 初始化公?
        byte[] pubKeyBytes = decryptBASE64(publicKey);

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        // 初始化私?
        byte[] priKeyBytes = decryptBASE64(privateKey);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
        Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory
                .getAlgorithm());
        keyAgree.init(priKey);
        keyAgree.doPhase(pubKey, true);

        // 生成本地密?
        SecretKey secretKey = keyAgree.generateSecret(SECRET_ALGORITHM);

        return secretKey;
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
