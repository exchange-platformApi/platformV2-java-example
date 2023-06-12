package com.chainup.open.exchangeplatformv2example.example;

import com.chainup.open.exchangeplatformv2example.utils.XRsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class XRsaDemo {

    public static void main(String[] args) {
        try {
            String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4AivV7eO95S3iL1OSl-NchS3LWtVrCxWBYer9s6TFc88CLNYmuVdb7FhA9nc2eBDWeSMosWHPVNpA0KKnMscajRJt6vKiBKmhZv81T4h9aXAtScw3EH1sYE_ia0N4LlOmPmgoSIJ4gQJQljHd2_45j32xZX-Hw-y9YrjsXU4fi6uNWqFZexfhwaYmLCkGm4-yb2Mf4bqooB2BwNxfsrt_jQokPqZfqOz7ktfY1zbThQ8VJPIbO3uYgjH3_pl1c_48dGAHBs4weC3taX3OpMBu7NYdiIkqOo6x9Q8Vs7Q-_dK0g6DqAy8nwOvgcf-KfH56e030LBDADGXxssYwwpPQIDAQAB";
            String privateKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCzgCK9Xt473lLeIvU5KX41yFLcta1WsLFYFh6v2zpMVzzwIs1ia5V1vsWED2dzZ4ENZ5IyixYc9U2kDQoqcyxxqNEm3q8qIEqaFm_zVPiH1pcC1JzDcQfWxgT-JrQ3guU6Y-aChIgniBAlCWMd3b_jmPfbFlf4fD7L1iuOxdTh-Lq41aoVl7F-HBpiYsKQabj7JvYx_huqigHYHA3F-yu3-NCiQ-pl-o7PuS19jXNtOFDxUk8hs7e5iCMff-mXVz_jx0YAcGzjB4Le1pfc6kwG7s1h2IiSo6jrH1DxWztD790rSDoOoDLyfA6-Bx_4p8fnp7TfQsEMAMZfGyxjDCk9AgMBAAECggEBAK93Un5LfnKHofoDsjNunDF24YlfD1Lu5m11Mgo2A4ccwDT90EelYzT2h53QcRAe3ch8ti0ySSuFn5_-HzHf5FI29D1K8W_8oPB_fnAfX9NpsbTSoWtr0n3glIDc1M5u5iVuAqcTZwU9vIp34qwPWMTjg2ZnMRd2XOxlL68hNDivhxhz3tv-8fK5k6noO3KzKU17sa9673tbcq73OEPF3Okv7Ypa6qohi5MqLMMhi6AErP_Q_K81KE58lDMVQkxBFSaSzgfMjbjvn1fYpLfpBmMRl3-eFJUvG7IzPTR6j4iofNG74WfxLlKx91CYwmgIr-0b36S3eOc1yz8J1FsNiAECgYEA6jvKqQgISKXkSjE0Fk5GDDI08wvd0Wg_e2FZFg_ZQ8RyZ9MfV9za3ATUweJUdDLgIi0poECR0m7e_SCznjLrb0ZjpzkpRscTWalDlIW_lVkXTDJO-yBoEmWCe_GgpyqRIuFoMiUwCN-rPtbOsGFnPqys_2M65eZ5SEFW2epUf2kCgYEAxC5LOwsjr3y-Tye8djBOhzAeQmamsBV-AGmNGsS3pD8sjWdG4tG01qRQ2y9_RIdCIvvrUYgwoocf7k7voTA8XmT3Ou6Oal74J-aU0SYCUBPJt1WvUmuRlBZN35TcUhquPgUb7SvbfOtNUc-gtCCK3KTPb-txXCzCXjFf_i8u9LUCgYEAsqKo-2Jp1uXVhhOiUsSdPV3o7dcF81da2sCyTVYG71zZl372r25650Mz8y2mFPxb3RSuY037KA5wN4ICGkthLHr1Myov5Y-bnUyugo3CP6czUmQnwfPECwupiNcNG5AmIgDgEyYzTQEvu3vdI70VHUJZqWfHGmA77LQQBZ9lk8kCgYAnj65cGcL4gI9gJwM6UkODv5Bak5jJqYvfSWnLHCBsXtD9MvZ4hxGQt1IW4V0o1J3hsCukJXKpU9Z8mC56st95qaKxn6nYiY5BfZ5FDwUoYNUsw3q3hDm3Q0gw7jP_2qGIoD8hdNauOkU9WkFuEaHvHM04JKKXk-8eT5asC5fMgQKBgQCCcn-7MWFumJfmCZOxBg0_pSPsbAlmSFxdOO1VQ9Q4Iny47AQRvYxbe-zdvpBzPbkoTlLraJ_hjg9dE2ZbxdiWVAkcTcHmzlCs4BKBQi8hu-z3cns5-TI-93wjrBjqAWL04nFA3wz043cXiOqhaykm3FZV1Dk4i-SZOZns6Zuukw";

            RSAPublicKey rsaPublicKey = XRsa.getRSAPublicKey(publicKey);
            RSAPrivateKey rsaPrivateKey = XRsa.getRSAPrivateKey(privateKey);


            String json = "{\"words\" : \"hello, open platform by rsa\"}";

            // 私钥加密得到sign
            String sign = XRsa.sign(json, rsaPrivateKey);
            System.out.println("sign:" + sign);
            boolean b = XRsa.verifySign(json, sign, rsaPublicKey);
            System.out.println("verify sign result :" + b);


            String en = XRsa.publicEncrypt(json, rsaPublicKey);

            String de = XRsa.privateDecrypt(en, rsaPrivateKey);

            System.out.println("公钥(public)加密,私钥(private)解密---------");
            System.out.println("公钥加密json数据:" + en);
            System.out.println("私钥解密:" + de);

            en = XRsa.privateEncrypt(json, rsaPrivateKey);
            de = XRsa.publicDecrypt(en, rsaPublicKey) ;

            System.out.println("私钥(private)加密，公钥(public)解密---------");
            System.out.println("私钥加密json数据:" + en);
            System.out.println("公钥解密:" + de);

            System.out.println("--------------------------------------------------------------------------------");


        } catch (Exception e) {
            System.out.println("Exception thrown: " + e);
        }
    }
}
