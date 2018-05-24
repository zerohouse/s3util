package com.zerohouse.s3util;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
public class S3Signature implements Serializable {

    public static final String PUBLIC_READ = "public-read";
    public static final String AWS4_HMAC_SHA256 = "AWS4-HMAC-SHA256";

    @JsonProperty("key")
    String filePath;

    String acl;

    @JsonProperty("Content-Type")
    String contentType;

    @JsonProperty("Policy")
    String policyBase64Encoded;

    @JsonProperty("X-Amz-Algorithm")
    String algorithm;

    @JsonProperty("X-Amz-Credential")
    String credential;

    @JsonProperty("X-Amz-Date")
    String amzDate;

    @JsonProperty("x-amz-meta-uuid")
    String metaUuid;

    @JsonProperty("X-Amz-Signature")
    String signature;

    @JsonProperty("Host")
    String host;


    public S3Signature(String host, String filePath, String contentType, String credential, String policyBase64Encoded, String signature, String metaUuid, String amzDate) {
        this.host = host;
        this.filePath = filePath;
        this.acl = PUBLIC_READ;
        this.contentType = contentType;
        this.credential = credential;
        this.policyBase64Encoded = policyBase64Encoded;
        this.signature = signature;
        this.metaUuid = metaUuid;
        this.amzDate = amzDate;
        algorithm = AWS4_HMAC_SHA256;
    }
}
