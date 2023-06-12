package com.chainup.open.exchangeplatformv2example.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;


import java.io.ByteArrayOutputStream;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;


public class XRsa {
    public static final String CHARSET = "UTF-8";
    public static final String RSA_ALGORITHM = "RSA";
    public static final String RSA_ALGORITHM_SIGN = "SHA256WithRSA";
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    public XRsa(String publicKey, String privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);

            // 通过X509编码的Key指令获得公钥对象
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));

            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
            // 通过PKCS#8编码的Key指令获得私钥对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        } catch (Exception e) {
            throw new RuntimeException("不支持的密钥: ", e);
        }
    }

    public static RSAPublicKey getRSAPublicKey(String publicKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            // 通过X509编码的Key指令获得公钥对象
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
            return (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
        } catch (Exception e) {
            throw new RuntimeException("getRSAPublicKey,不支持的密钥: ", e);
        }
    }

    public static RSAPrivateKey getRSAPrivateKey(String privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            // 通过PKCS#8编码的Key指令获得私钥对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
            return (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        } catch (Exception e) {
            throw new RuntimeException("getRSAPrivateKey,不支持的密钥: ", e);
        }
    }


    public static Map<String, String> createKeys(int keySize) {
        // 为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg;

        try {
            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm -> [" +
                RSA_ALGORITHM + "]");
        }

        // 初始化KeyPairGenerator对象,不要被initialize()源码表面上欺骗,其实这里声明的size是生效的
        kpg.initialize(keySize);

        // 生成秘钥对
        KeyPair keyPair = kpg.generateKeyPair();

        // 得到公钥
        Key publicKey = keyPair.getPublic();
        String publicKeyStr = Base64.encodeBase64URLSafeString(publicKey.getEncoded());

        // 得到私钥
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = Base64.encodeBase64URLSafeString(privateKey.getEncoded());
        Map<String, String> keyPairMap = new HashMap<>();
        keyPairMap.put("publicKey", publicKeyStr);
        keyPairMap.put("privateKey", privateKeyStr);

        return keyPairMap;
    }

    /**
     * 公钥加密
     */
    public String publicEncrypt(String data) {
        return publicKeyEncrypt(data, publicKey);
    }
    public static String publicEncrypt(String data, RSAPublicKey rsaPublicKey) {
        return publicKeyEncrypt(data, rsaPublicKey);
    }

    private static String publicKeyEncrypt(String data, RSAPublicKey rsaPublicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

            return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher,
                    Cipher.ENCRYPT_MODE, data.getBytes(CHARSET),
                    rsaPublicKey.getModulus().bitLength()));
        } catch (Exception e) {
            throw new RuntimeException("公钥加密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 私钥解密
     */
    public String privateDecrypt(String data) {
        return privateKeyDecrypt(data, privateKey, publicKey.getModulus());
    }
    public static String privateDecrypt(String data, RSAPrivateKey rsaPrivateKey) {
        return privateKeyDecrypt(data, rsaPrivateKey, rsaPrivateKey.getModulus());
    }

    private static String privateKeyDecrypt(String data, RSAPrivateKey rsaPrivateKey, BigInteger modulus) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);

            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data),
                    modulus.bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("私钥解密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 私钥加密
     */
    public String privateEncrypt(String data) {
        return privateKeyEncrypt(data, privateKey, publicKey.getModulus());
    }
    public static String privateEncrypt(String data, RSAPrivateKey rsaPrivateKey) {
        return privateKeyEncrypt(data, rsaPrivateKey, rsaPrivateKey.getModulus());
    }

    private static String privateKeyEncrypt(String data, RSAPrivateKey rsaPrivateKey, BigInteger modulus) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);

            return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher,
                    Cipher.ENCRYPT_MODE, data.getBytes(CHARSET),
                    modulus.bitLength()));
        } catch (Exception e) {
            throw new RuntimeException("私钥加密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 公钥解密
     */
    public String publicDecrypt(String data) {
        return publicKeyDecrypt(data, publicKey);
    }
    public static String publicDecrypt(String data, RSAPublicKey rsaPublicKey) {
        return publicKeyDecrypt(data, rsaPublicKey);
    }

    private static String publicKeyDecrypt(String data, RSAPublicKey rsaPublicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);

            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE,
                    Base64.decodeBase64(data),
                    rsaPublicKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("公钥解密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 私钥签名
     */
    public String sign(String data) {
        return getSign(data, privateKey);
    }

    public static String sign(String data, RSAPrivateKey privateKey) {
        return getSign(data, privateKey);
    }

    private static String getSign(String data, RSAPrivateKey privateKey) {
        try {
            String encodeStr = DigestUtils.md5Hex(data);
            Signature signature = Signature.getInstance(RSA_ALGORITHM_SIGN);
            signature.initSign(privateKey);
            signature.update(encodeStr.getBytes(CHARSET));

            return Base64.encodeBase64URLSafeString(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException("私钥签名字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 公钥验签，验证sign
     */
    public boolean verify(String data, String sign) {
        return verifySign(data, sign, publicKey);
    }

    public static boolean verify(String data, String sign, RSAPublicKey rsaPublicKey) {
        return verifySign(data, sign, rsaPublicKey);
    }

    public static boolean verifySign(String data, String sign, RSAPublicKey rsaPublicKey) {
        try {
            String encodeStr = DigestUtils.md5Hex(data);
            Signature signature = Signature.getInstance(RSA_ALGORITHM_SIGN);
            signature.initVerify(rsaPublicKey);
            signature.update(encodeStr.getBytes(CHARSET));

            return signature.verify(Base64.decodeBase64(sign));
        } catch (Exception e) {
            throw new RuntimeException("公钥验签字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 分段加解密
     */
    private static byte[] rsaSplitCodec(Cipher cipher, int opmode,
        byte[] datas, int keySize) {
        int maxBlock = 0;

        if (opmode == Cipher.DECRYPT_MODE) {
            maxBlock = keySize / 8;
        } else {
            maxBlock = (keySize / 8) - 11;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buff;
        int i = 0;

        try {
            while (datas.length > offSet) {
                if ((datas.length - offSet) > maxBlock) {
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                } else {
                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                }

                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
        } catch (Exception e) {
            throw new RuntimeException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
        }

        byte[] resultDatas = out.toByteArray();
        IOUtils.closeQuietly(out);

        return resultDatas;
    }
}
