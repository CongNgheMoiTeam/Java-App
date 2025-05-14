// /*
//  * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
//  * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
//  */
// package com.example.taskmanager.security;

// import javax.crypto.Cipher;
// import javax.crypto.SecretKey;
// import javax.crypto.spec.SecretKeySpec;
// import java.nio.charset.StandardCharsets;
// import java.security.MessageDigest;
// import java.util.Arrays;
// import java.util.Base64;

// public class EncryptionUtil {
//     private static final String ALGORITHM = "AES";
//     private static final String SECRET_KEY = "TaskManagerSecretKey";

//     private static SecretKey getSecretKey() throws Exception {
//         MessageDigest sha = MessageDigest.getInstance("SHA-256");
//         byte[] key = sha.digest(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
//         key = Arrays.copyOf(key, 16); // AES-128 needs 16 bytes
//         return new SecretKeySpec(key, ALGORITHM);
//     }

//     public static String encrypt(String data) {
//         try {
//             SecretKey secretKey = getSecretKey();
//             Cipher cipher = Cipher.getInstance(ALGORITHM);
//             cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//             return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
//         } catch (Exception e) {
//             System.err.println("Error during encryption: " + e.getMessage());
//             return null;
//         }
//     }

//     public static String decrypt(String encryptedData) {
//         try {
//             SeretKey secretKey = getSecretKey();
//             Cipher cipher = Cipher.getInstance(ALGORITHM);
//             cipher.init(Cipher.DECRYPT_MODE, secretKey);
//             return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)));
//         } catch (Exception e) {
//             System.err.println("Error during decryption: " + e.getMessage());
//             return null;
//         }
//     }
// }
package com.example.taskmanager.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY = "MeoMeoMeoGauGauGau240!ecec";

    private static SecretKey getSecretKey() throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(key, "AES"); // AES-256 nếu key đủ 32 byte
    }

    public static String encrypt(String data) {
        try {
            SecretKey secretKey = getSecretKey();

            // Tạo IV ngẫu nhiên
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // Gắn IV vào đầu ciphertext giống PHP, rồi base64 encode
            byte[] combined = new byte[ivBytes.length + encryptedBytes.length];
            System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
            System.arraycopy(encryptedBytes, 0, combined, ivBytes.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            System.err.println("Error during encryption: " + e.getMessage());
            return null;
        }
    }

    public static String decrypt(String encryptedData) {
        try {
            SecretKey secretKey = getSecretKey();
            byte[] allBytes = Base64.getDecoder().decode(encryptedData);

            byte[] ivBytes = Arrays.copyOfRange(allBytes, 0, 16);
            byte[] cipherBytes = Arrays.copyOfRange(allBytes, 16, allBytes.length);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            byte[] originalBytes = cipher.doFinal(cipherBytes);
            return new String(originalBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
            return null;
        }
    }
}

