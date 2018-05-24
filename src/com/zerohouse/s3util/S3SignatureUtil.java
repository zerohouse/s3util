package com.zerohouse.s3util;

import com.amazonaws.regions.Regions;
import lombok.AllArgsConstructor;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;


@AllArgsConstructor
public class S3SignatureUtil {

    private String accessKey;
    private String secretKey;
    private String bucketName;
    private Regions regions;

    private static final String S3 = "s3";
    private static final String CREDENTIAL = "%s/%s/%s/%s/aws4_request";
    private static final String UPLOAD_POLICY_FORMAT = "{ \"expiration\": \"%s\",\"conditions\": [{\"bucket\": \"%s\"}, " +
            "[\"starts-with\", \"$key\", \"%s\"],{\"acl\": \"public-read\"}, " +
            "[\"starts-with\", \"$Content-Type\", \"%s\"], {\"x-amz-meta-uuid\": \"%s\"}, {\"x-amz-CREDENTIAL\": \"%s\"}, " +
            "{\"x-amz-algorithm\": \"AWS4-HMAC-SHA256\"},{\"x-amz-date\": \"%s\"},[\"content-length-range\", 0, %d]]}";

    public S3Signature getSignature(String contentType, String filePath, Date expired, Long size) throws Exception {
        Date now = new Date();
        SimpleDateFormat expiredFormat = new SimpleDateFormat("YYYY-MM-dd'T'HH:mm:ss'Z'");
        SimpleDateFormat createTime = new SimpleDateFormat("YYYYMMdd");
        SimpleDateFormat amz_date = new SimpleDateFormat("YYYYMMdd'T'HHmmss'Z'");
        String credTime = createTime.format(now);
        String amzDate = amz_date.format(now);
        String uuid = UUID.randomUUID().toString();
        String credential = getCredential(accessKey, credTime, regions.getName(), S3);
        String stringToSigned = getStringToSign(expiredFormat.format(expired), credential, amzDate, filePath, uuid, contentType, size);
        byte[] signKey;
        signKey = getSignatureKey(credTime);
        String signature = bytesToHex(hmacSHA256(stringToSigned, signKey));
        return new S3Signature(String.format("%s.%s.amazonaws.com", bucketName, S3), filePath, contentType, credential, stringToSigned, signature, uuid, amzDate);
    }

    private byte[] getSignatureKey(String yyyymmdd) throws Exception {
        byte[] kSecret = ("AWS4" + secretKey).getBytes("UTF8");
        byte[] kDate = hmacSHA256(yyyymmdd, kSecret);
        byte[] kRegion = hmacSHA256(regions.getName(), kDate);
        byte[] kService = hmacSHA256(S3, kRegion);
        return hmacSHA256("aws4_request", kService);
    }


    public static byte[] hmacSHA256(String data, byte[] key) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    private final static char[] hexArray = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private String uploadPolicy(String expired, String credential, String amz_time, String filePath, String contentType, String uuid, Long size) {
        return String.format(
                UPLOAD_POLICY_FORMAT,
                expired,
                bucketName,
                filePath,
                contentType,
                uuid,
                credential,
                amz_time,
                size);
    }

    private String getCredential(String accessKeyId, String credTime, String region, String serviceName) {
        return String.format(CREDENTIAL, accessKeyId, credTime, region, serviceName);
    }

    private String getStringToSign(String expired, String credential, String amz_time, String filePath, String uuid, String contentType, Long size) {
        String json = uploadPolicy(expired, credential, amz_time, filePath, contentType, uuid, size);
        return new String(Base64.encodeBase64(json.getBytes()));
    }


}
