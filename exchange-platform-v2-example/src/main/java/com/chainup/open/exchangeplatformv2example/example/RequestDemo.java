package com.chainup.open.exchangeplatformv2example.example;

import com.alibaba.fastjson.JSONObject;
import com.chainup.open.exchangeplatformv2example.utils.HttpUtils;
import com.chainup.open.exchangeplatformv2example.utils.XRsa;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class RequestDemo {

    public static void main(String[] args) {

        String appId = "xxxx";

        String baasUrl = "http://service.xxxx.com/platformapi/chainup/open/user/registerOrLoginToGetOpenApi";

        String oppositePublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhX2uNtofc_upYCp4AN78KWgDwl99rThGQurBEC466uJY5z9IuX5oA7z1ReUTsN83k2NycJEZBu-hUkKLyBKIVCau_qpPBFGZq9has0xSp1afssDgI67hXLOft7tI7GnSypU7glDCNBHeyBU843qKXdlDG3Nis9_EYHI6OeI7aun_4zfToABdf2qVNTwBz1LYQo6jPms5oCtxBbjCH0vLA8JdoDTeT11rsqKJLtRZI1Ve0TRGBmX6f-ygoRJSu1AquzECf7HD3FW_56DS2wRnZFFsvOefYiAVU97VKlvQOXIXnoct2oyVvO__SzrRPusLDNc0Hk7ZMZrZqoyHuYDgJQIDAQAB";
        String myPrivateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCSxyVJwHCf_SsSDKZVlw1yKbjuZnBVkkueEraXPy05rKvmoJLMySa2tEKYdDOy1HoqYS7v_so0Zv2tVQEUyHobTgamasB-yE6Ah29QZRSo-e4TCAAFaV8CUZulSGPL2xJGB31ssHE6tE7S4Iq_E-0R1c80xSntJsd4ozMyaDEp9aPimK_mNCNWwISd8EHwygUB8rVIM0KZGSXHjh1qbYLe5EXrWFeRa8oeLcYaYldtF90eYeyU_b02ZJhB_iKB13WvZ_qNVLBvk82VuxXW2A6uqnTR1kpogewEeiXooDq1hsEzKpZREWNbMSqoMA1hXOWBIDz7aPVQtkUDQvQb4UGXAgMBAAECggEAXwXGQiTvxOPlyl2eIbMU5V_VdaGkAAIiKkf7JZek872x3DEAWMuw4H96zbAM-C1Ombko5f6RcbNrb5ekh4vyYVL2Qy7BSFLtX5BOpEGMSojjdDatrNM2yw2CMlLXKNa-0c9vh7oC0_p_PU5ZBLMlu3IsHwG1zu5YHOWq82s4yOxfEoIJeomfaW48rdlWGUL6Ke2cfE_wUV2zEwDLIDhd8B71BnWdvIjr-dp05un58FnSo9NlFEtORDMISkzYnjBzoK39RWBg8vEV4BHbYpw7N6AAUpSm-I08OQ5IZgqnnRbJN2cVD-CuTMheVqloEkjaaBv_ylW0NOUUvWEQK7vtAQKBgQDFOM-2rYOkXtOp891bZf7ayX_IspLUBm4sJM0BA6mMIQwNuQ462U3_NVXcQGmsCKaOnngziSuNBON824cf-Ik43zmyTbS6ibCqHSJJTaMCEyZ0nBsmh68AjuiLg8BF_Yt4P3m6zKLUcAaltMDtbLsTTX9dGF9Z3VwJVf5Rs_jDIQKBgQC-hawh3H_Hnttqe_zp9CLsW2XUE2pwKHACuvyXREFnkd1_h-2_D_nUEGj_GyqyO48xHg6xNETcwvt38zByGBsh_g06yPea1zmb_ow6WPCE2VSA4dT0is41cX-8AxwQ9UtNgA7opyz-lRvTkIGYgwXnoLRBbS1iVNy4og7_P5oltwKBgD2Mtl53ll7k7T_cCJguo7PaMNQMzv_2pcmHDqejYfWGlsFtoIBDMzFTjuE3BQOYi4p08GR9CadwACMGTAxxPzoNiG8aCy4wLH9aqkmgPiA2o8i-s0Z6D-ansvFfg9EUCMPVY4MlvCd6csiiOZefWF70z6vZIGDmUYPkX4NWHGuhAoGAGXFge2Um61Gbm6zTKasgvs-12Yx-OlwsGTE_ajQDSAGCwvU0Gr_XbSqD2w2VtheeF8Eb1S5Vw-WGD466eYIenXt_6MnNxy_W0a48q84U0Kj1UADYn4-p2hk-Ja2Eof8f_0mKtCcfKyBehvJVXDijITuk1tftp6QNldqOhifIPiECgYAb7XuQc9qXCpOULK7MOY8rzKQd-MgFOm9UomcGZ9iW5sTxvPFiYIYFVo0iyko3BILe47oKfBxU4-JBn1c8sfaJRtn6d5reI1CQk3SnHGvlwn-ML9hPD-cXy7tXOHVSduoCS1poX6PA5o33AQnVyDKL6YHmfk9oqkFVaVVZBrT5Vw";

        // query params
        Map<String, String> params = new HashMap<>();
        params.put("countryCode", "+86");
        params.put("mobileNumber", "20231415161");
        params.put("password", "1234qwer");

        String jsonData = JSONObject.toJSONString(params);

        RSAPublicKey rsaPublicKey = XRsa.getRSAPublicKey(oppositePublicKey);
        // rsa_saas_pub --> data
        String data = XRsa.publicEncrypt(jsonData, rsaPublicKey);


        RSAPrivateKey rsaPrivateKey = XRsa.getRSAPrivateKey(myPrivateKey);
        // rsa_third_pri --> sign
        String sign = XRsa.sign(jsonData, rsaPrivateKey);

        log.info("sign : {}", sign);
        log.info("data : {}", data);

        // request body
        HashMap<String, Object> reqParams = new HashMap<>();
        reqParams.put("sign", sign);
        reqParams.put("data", data);
        reqParams.put("app_id", appId);
        reqParams.put("time", System.currentTimeMillis());

        String result = HttpUtils.sendPost(baasUrl, JSONObject.toJSONString(reqParams));

        log.info("request result : {}", result);

        JSONObject jsonObject = JSONObject.parseObject(result);

        String baasData = jsonObject.getString("data");
        if (StringUtils.isNotBlank(baasData)) {
            // rsa_third_pri --> data
            baasData = XRsa.privateDecrypt(baasData, rsaPrivateKey);

            // do something
            log.info("data: {}", baasData);
        } else {
            // do something
        }

        String baasSign = jsonObject.getString("sign");
        // rsa_saas_pub verify sign
        if (StringUtils.isNotBlank(baasSign)) {
            boolean verify = XRsa.verify(baasData, baasSign, rsaPublicKey);
            if (verify) {
                log.info("verify is success");
            } else {
                // do something
                log.error("verify is error {}", jsonData);
            }
        }
    }
}
