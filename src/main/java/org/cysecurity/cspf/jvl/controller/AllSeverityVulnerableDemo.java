package com.opsera.vulnerable;

import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AllSeverityVulnerableDemo extends HttpServlet {

    // Hardcoded secret (for key and info exposure)
    private static final String SECRET_KEY = "1234567890123456"; // WARNING: Hardcoded key

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
        double randomValue = Math.random(); // Not secure
        SecureRandom secureRandom = new SecureRandom(); // Secure, for contrast

        // LOW: Information Exposure
        String secret = "mySecretPassword";
        System.out.println("User password is: " + secret);

        // WARNING: Hardcoded cryptographic key
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal("SensitiveData".getBytes());
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        // NOTE: Use of deprecated API
        Thread thread = new Thread();
        thread.stop();

        // NOTE: Empty catch block (CodeQL note)
        try {
            int x = 1 / 0;
        } catch (Exception e) {
            // empty catch block
        }

        // WARNING: Insecure deserialization
        try {
            byte[] data = Base64.getDecoder().decode("rO0ABXQAB0hlbGxvIQ==");
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
        } catch (Exception e) {
            // ignore
        }

        // ERROR: Cleartext storage in cookie (simulated, would be flagged in a servlet context)
        Cookie cookie = new Cookie("auth", "user=admin; password=" + secret);
        System.out.println("Set-Cookie: " + cookie.getValue());

        // WARNING/MEDIUM: Weak hash
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest("test".getBytes());
        System.out.println("MD5 hash: " + Base64.getEncoder().encodeToString(hash));
    }

    // Servlet method to demonstrate cleartext cookie in a web context
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String secret = "webSecret";
        Cookie cookie = new Cookie("auth", "user=admin; password=" + secret);
        resp.addCookie(cookie);
        resp.getWriter().println("Cookie set: " + cookie.getValue());
    }
} 
