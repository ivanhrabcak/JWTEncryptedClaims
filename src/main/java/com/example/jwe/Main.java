package com.example.jwe;

//    public static PublicKey readPublicKey(Path file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
//        byte[] keyBytes = Files.readAllBytes(file);
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePublic(spec);
//    }
//
//    public static PrivateKey readPrivateKey(Path file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
//        byte[] keyBytes = Files.readAllBytes(file);
//        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePrivate(spec);
//    }

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.*;

public class Main {
    public static Base64.Encoder base64 = Base64.getEncoder();
    public static Base64.Decoder base64Decoder = Base64.getDecoder();

    public static URL getFileResourcePath(String relativePath) {
        return Main.class.getClassLoader().getResource(relativePath);
    }

//    public static String encryptString(String input, PublicKey key) {
//        try {
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.ENCRYPT_MODE, key);
//            return new String(cipher.doFinal(base64.encode(input.getBytes())));
//        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
//            e.printStackTrace();
//            return null;
//        }
//    }
//
//    public static String decryptString(String input, PrivateKey key) {
//        try {
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, key);
//            byte[] decipheredBytes = cipher.doFinal(input.getBytes());
//            return new String(base64Decoder.decode(decipheredBytes));
//        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
//            e.printStackTrace();
//            return null;
//        }
//    }

    public static void main(String[] args) throws ParseException, NoSuchAlgorithmException, IOException {

        Date now = new Date();

        // add all claims that you want to encrypt
        JSONObject encryptedClaimsObject = new JSONObject();

        encryptedClaimsObject.put("email", "ivan@hrabcak.eu");
        encryptedClaimsObject.put("github", "https://github.com/ivanhrabcak/JWTEncryptedClaims");

        System.out.println("Encrypted claims:");
        System.out.println(encryptedClaimsObject.toString());

        // a AES key to encrypt the claim
        String secretKey = "supertajneheslo";

        System.out.println("\nSymmetric Key: (koe claim)");
        System.out.println(secretKey);

        SecureRandom secureRandom = new SecureRandom();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        System.out.println("\nPublic Key:\n");
        System.out.println(keyPair.getPublic().toString());

        String hybridEncryptedKey = base64.encodeToString(RSAUtils.encrypt(keyPair.getPublic(), secretKey.getBytes()));
        System.out.println("\nBase64 encoded, encrypted symmetric key:");
        System.out.println(hybridEncryptedKey);

        String encryptedClaims = AES.encrypt(encryptedClaimsObject.toString(), secretKey);

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer("sso.csob.sk")
                .subject("alice")
                .audience(Collections.singletonList("klient.csob.sk"))
                .expirationTime(new Date(now.getTime() + 1000 * 60 * 10))
                .notBeforeTime(now)
                .issueTime(now)
                .claim("koe", hybridEncryptedKey)
                .claim("ecs", encryptedClaims)
                .jwtID(UUID.randomUUID().toString())
                .build();

        System.out.println("\nEncrypted claims: (ecs claim)");
        System.out.println(encryptedClaims);

        PlainHeader header = new PlainHeader();

        JWT jwt = new PlainJWT(header, jwtClaims);

        System.out.println("\nJWT token with encrypted email claim:");
        System.out.println(jwt.serialize());

        JWT parsedJWT = PlainJWT.parse(jwt.serialize());

        Map<String, Object> claims = parsedJWT.getJWTClaimsSet().getClaims();

        byte[] encryptedKey = base64Decoder.decode(((String) claims.get("koe")).getBytes());

        String key = new String(RSAUtils.decrypt(keyPair.getPrivate(), encryptedKey));

        String decryptedClaims = AES.decrypt((String) claims.get("ecs"), key);

        JSONObject decryptedClaimsObject = new JSONObject(decryptedClaims);

        System.out.println("\nClaims derived from JWT token:");
        System.out.println(decryptedClaimsObject.toString());
    }
}
