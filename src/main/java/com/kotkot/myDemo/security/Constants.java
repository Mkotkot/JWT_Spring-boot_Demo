package com.kotkot.myDemo.security;

public interface Constants {
    String AUTHENTICATION_HEADER = "Authentication";
    String AUTHORITIES_BODY = "authorities";
    String TOKEN_PREFIX = "Bearer ";
    String SECRET_KEY_TEXT = "SecureSecureSecureSecureSecureSecureSecureSecure";
    long EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 10; // 10 days

}

