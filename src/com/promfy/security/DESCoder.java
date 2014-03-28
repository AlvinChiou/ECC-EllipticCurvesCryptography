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
 * DES-Data Encryption Standard,�Y?�u�[�K��k�C�OIBM���q�_1975�~��s���\�}��??���CDES��k���J�f??���T?:Key�BData�BMode�C�䤤Key?8?�r?�@64��,�ODES��k���u�@�K?;Data�]?8?�r?64��,�O�n�Q�[�K�γQ�ѱK��?�u;Mode?DES���u�@�覡,��?��:�[�K�θѱK�C 
 * DES��k��64�쪺����?�J???64�쪺�K��?�X?,���ҨϥΪ��K?�]�O64��C 
 */



/**
 * DES�w��???��
 *
 * <pre>
 * ��� DES�BDESede(TripleDES,�N�O3DES)�BAES�BBlowfish�BRC2�BRC4(ARCFOUR)
 * DES                          key size must be equal to 56
 * DESede(TripleDES)    key size must be equal to 112 or 168
 * AES                          key size must be equal to 128, 192 or 256,but 192 and 256 bits may not be available
 * Blowfish                     key size must be multiple of 8, and can only range from 32 to 448 (inclusive)
 * RC2                          key size must be between 40 and 1024 bits
 * RC4(ARCFOUR)                 key size must be between 40 and 1024 bits
 * ���^?�e �ݭn?�` JDK Document http://.../docs/technotes/guides/security/SunProviders.html
 * </pre>
 *
 * @author ��?
 * @version 1.0
 * @since 1.0
 */
public abstract class DESCoder extends Coder {
    /**
     * ALGORITHM ��k <br>
     * �i��??�H�U���N�@����k�A�P?key�Ȫ�size��?��?�C
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
     * �bKey toKey(byte[] key)��k���ϥΤU�z�N?
     * <code>SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);</code> ��?
     * <code>
     * DESKeySpec dks = new DESKeySpec(key);
     * SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
     * SecretKey secretKey = keyFactory.generateSecret(dks);
     * </code>
     */
    public static final String ALGORITHM = "DES";

    /**
     * ??�K?<br>
     *
     * @param key
     * @return
     * @throws Exception
     */
    private static Key toKey(byte[] key) throws Exception {
        DESKeySpec dks = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(dks);

        // ?�ϥΨ�L??�[�K��k?�A�pAES�BBlowfish����k?�A�ΤU�z�N?��?�W�z�T��N?
        // SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

        return secretKey;
    }

    /**
     * �ѱK
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
     * �[�K
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
     * �ͦ��K?
     *
     * @return
     * @throws Exception
     */
    public static String initKey() throws Exception {
        return initKey(null);
    }

    /**
     * �ͦ��K?
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
