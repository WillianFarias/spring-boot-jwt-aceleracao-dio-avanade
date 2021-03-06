package com.avanade.dio.jwt.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.avanade.dio.jwt.data.UserData;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  //filtros em java sao interceptadores, capturam uma requisicao e fazem algo com ela

  private final AuthenticationManager authenticationManager;

  public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
      throws AuthenticationException {
    try {
      // UserData sao os dados que estaram dentro do token
      UserData creds = new ObjectMapper().readValue(req.getInputStream(), UserData.class);

      //Leio meu toke acima e autentico aqui (ler o token e autenticar)
      return authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(
           creds.getUserName(),
           creds.getPassword(),
           new ArrayList<>()));
    } catch (IOException e) {
      throw new RuntimeException("Usuário não autenticado " + e);
    }
  }

  // apos autenticar o token sera gerado pelo auth0
  @Override
  protected void successfulAuthentication(HttpServletRequest req,
    HttpServletResponse res,
    FilterChain chain,
    Authentication auth) throws IOException, ServletException {
      //Depois de autenticado eu gero o token
      String token = JWT.create()
      //posso estar passando quaisquer informacoes dentro do meu jwt, por exemplo
      //o saldo do cartao do meu cliente
        .withSubject(((User) auth.getPrincipal()).getUsername())
        .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
        .sign(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()));

      //o token sera adicionado no head to retorno da requisicao
      res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
    }
}
