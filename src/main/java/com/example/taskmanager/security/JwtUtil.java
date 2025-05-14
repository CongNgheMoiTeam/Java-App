// /*
//  * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
//  * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
//  */
// package com.example.taskmanager.security;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.function.Function;

// public class JwtUtil {
//     private final String SECRET_KEY = "your_secret_key_here_should_be_long_and_secure";
//     private final long TOKEN_VALIDITY = 3600 * 5; // 5 hours in seconds

//     public String extractUsername(String token) {
//         return extractClaim(token, Claims::getSubject);
//     }

//     public Date extractExpiration(String token) {
//         return extractClaim(token, Claims::getExpiration);
//     }

//     public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//         final Claims claims = extractAllClaims(token);
//         return claimsResolver.apply(claims);
//     }

//     private Claims extractAllClaims(String token) {
//         return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
//     }

//     private Boolean isTokenExpired(String token) {
//         return extractExpiration(token).before(new Date());
//     }

//     public String generateToken(String username) {
//         Map<String, Object> claims = new HashMap<>();
//         return createToken(claims, username);
//     }

//     private String createToken(Map<String, Object> claims, String subject) {
//         return Jwts.builder()
//                 .setClaims(claims)
//                 .setSubject(subject)
//                 .setIssuedAt(new Date(System.currentTimeMillis()))
//                 .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000))
//                 .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
//                 .compact();
//     }

//     public Boolean validateToken(String token, String username) {
//         final String extractedUsername = extractUsername(token);
//         return (extractedUsername.equals(username) && !isTokenExpired(token));
//     }
// }
package com.example.taskmanager.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtUtil {
    private final String SECRET_KEY = "Khoa010103"; // Giống PHP
    private final long TOKEN_VALIDITY = 3600; // 1 giờ

    // Tạo JWT tương thích với PHP
    public String generateToken(String googleId, String role) throws Exception {
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        long issuedAt = System.currentTimeMillis() / 1000;
        long expiration = issuedAt + TOKEN_VALIDITY;

        Map<String, Object> payload = new HashMap<>();
        payload.put("iss", "API_Security");
        payload.put("aud", "user");
        payload.put("iat", issuedAt);
        payload.put("exp", expiration);

        Map<String, String> data = new HashMap<>();
        data.put("GoogleID", googleId);
        data.put("role", role);
        payload.put("data", data);

        String headerBase64 = base64UrlEncode(new ObjectMapper().writeValueAsBytes(header));
        String payloadBase64 = base64UrlEncode(new ObjectMapper().writeValueAsBytes(payload));
        String signature = sign(headerBase64 + "." + payloadBase64);

        return headerBase64 + "." + payloadBase64 + "." + signature;
    }

    // Giải mã và xác minh JWT giống PHP
    public boolean verifyToken(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) return false;

        String headerBase64 = parts[0];
        String payloadBase64 = parts[1];
        String signatureBase64 = parts[2];

        String expectedSignature = sign(headerBase64 + "." + payloadBase64);
        if (!signatureBase64.equals(expectedSignature)) return false;

        String payloadJson = new String(Base64.getUrlDecoder().decode(payloadBase64));
        Map payload = new ObjectMapper().readValue(payloadJson, Map.class);

        long exp = ((Number) payload.get("exp")).longValue();
        return exp > (System.currentTimeMillis() / 1000);
    }

    // Ký bằng HMAC SHA-256 và base64url encode
    private String sign(String data) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256"));
        byte[] rawHmac = hmac.doFinal(data.getBytes());
        return base64UrlEncode(rawHmac);
    }

    // Base64 URL encode (không padding)
    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
