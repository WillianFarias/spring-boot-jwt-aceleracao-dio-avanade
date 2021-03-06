package com.avanade.dio.jwt.security;

public class SecurityConstants {
  
  //chave que vai compor a chave encriptada
  public static final String SECRET = "SecretKeyToGenJWTs";
  public static final long EXPIRATION_TIME = 864_000_000; // 10 days
  public static final String TOKEN_PREFIX = "Bearer";
  public static final String HEADER_STRING = "Authorization";

  //urls que ignoram a autenticacao
  public static final String SIGN_UP_URL = "/login";
  public static final String STATUS_URL = "/status";
}
