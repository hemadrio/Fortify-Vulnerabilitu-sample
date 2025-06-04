package com.opsera.vulnerable;

import java.io.*;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AllSeverityVulnerableDemo {

    public static void main(String[] args) throws Exception {
        // CRITICAL: Command Injection
        String userInput = args.length > 0 ? args[0] : "ls";
        Runtime.getRuntime().exec("sh -c " + userInput);

        // HIGH: SQL Injection
        String username = "admin";
        String password = "admin' OR '1'='1";
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'");

        // MEDIUM: Insecure Randomness
        double randomValue = Math.random();

        // LOW: Information Exposure
        String secret = "mySecretPassword";
        System.out.println("User password is: " + secret);

        // WARNING: Hardcoded cryptographic key
        String key = "1234567890123456"; // 16-char key for AES
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal("SensitiveData".getBytes());
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        // NOTE: Use of deprecated API
        Thread thread = new Thread();
        thread.stop();

        // ERROR: Cleartext storage in cookie (simulated)
        String cookieValue = "user=admin; password=" + secret;
        System.out.println("Set-Cookie: " + cookieValue);

        // Additional: Weak hash (often flagged as warning/medium)
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest("test".getBytes());
        System.out.println("MD5 hash: " + Base64.getEncoder().encodeToString(hash));
    }
} 
