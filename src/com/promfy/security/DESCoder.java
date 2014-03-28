package com.promfy.security;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
/**
 * DES 
 * DES-Data Encryption Standard,即?据加密算法。是IBM公司于1975年研究成功并公??表的。DES算法的入口??有三?:Key、Data、Mode。其中Key?8?字?共64位,是DES算法的工作密?;Data也?8?字?64位,是要被加密或被解密的?据;Mode?DES的工作方式,有?种:加密或解密。 
 * DES算法把64位的明文?入???64位的密文?出?,它所使用的密?也是64位。 
 */



/**
 * DES安全???件
 *
 * <pre>
 * 支持 DES、DESede(TripleDES,就是3DES)、AES、Blowfish、RC2、RC4(ARCFOUR)
 * DES                          key size must be equal to 56
 * DESede(TripleDES)    key size must be equal to 112 or 168
 * AES                          key size must be equal to 128, 192 or 256,but 192 and 256 bits may not be available
 * Blowfish                     key size must be multiple of 8, and can only range from 32 to 448 (inclusive)
 * RC2                          key size must be between 40 and 1024 bits
 * RC4(ARCFOUR)                 key size must be between 40 and 1024 bits
 * 具体?容 需要?注 JDK Document http://.../docs/technotes/guides/security/SunProviders.html
 * </pre>
 *
 * @author 梁?
 * @version 1.0
 * @since 1.0
 */
public abstract class DESCoder extends Coder {
    /**
     * ALGORITHM 算法 <br>
     * 可替??以下任意一种算法，同?key值的size相?改?。
     *
     * <pre>
     * DES                          key size must be equal to 56
     * DESede(TripleDES)    key size must be equal to 112 or 168
     * AES                          key size must be equal to 128, 192 or 256,but 192 and 256 bits may not be available
     * Blowfish                     key size must be multiple of 8, and can only range from 32 to 448 (inclusive)
     * RC2                          key size must be between 40 and 1024 bits
     * RC4(ARCFOUR)                 key size must be between 40 and 1024 bits
     * </pre>
     *
     * 在Key toKey(byte[] key)方法中使用下述代?
     * <code>SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);</code> 替?
     * <code>
     * DESKeySpec dks = new DESKeySpec(key);
     * SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
     * SecretKey secretKey = keyFactory.generateSecret(dks);
     * </code>
     */
    public static final String ALGORITHM = "DES";

    /**
     * ??密?<br>
     *
     * @param key
     * @return
     * @throws Exception
     */
    private static Key toKey(byte[] key) throws Exception {
        DESKeySpec dks = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(dks);

        // ?使用其他??加密算法?，如AES、Blowfish等算法?，用下述代?替?上述三行代?
        // SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

        return secretKey;
    }

    /**
     * 解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String key) throws Exception {
        Key k = toKey(decryptBASE64(key));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, k);

        return cipher.doFinal(data);
    }

    /**
     * 加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, String key) throws Exception {
        Key k = toKey(decryptBASE64(key));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, k);

        return cipher.doFinal(data);
    }

    /**
     * 生成密?
     *
     * @return
     * @throws Exception
     */
    public static String initKey() throws Exception {
        return initKey(null);
    }

    /**
     * 生成密?
     *
     * @param seed
     * @return
     * @throws Exception
     */
    public static String initKey(String seed) throws Exception {
        SecureRandom secureRandom = null;

        if (seed != null) {
            secureRandom = new SecureRandom(decryptBASE64(seed));
        } else {
            secureRandom = new SecureRandom();
        }

        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
        kg.init(secureRandom);

        SecretKey secretKey = kg.generateKey();

        return encryptBASE64(secretKey.getEncoded());
    }
}
