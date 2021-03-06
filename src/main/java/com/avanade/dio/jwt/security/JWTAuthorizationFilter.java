package com.avanade.dio.jwt.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.rowset.serial.SerialException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

  public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
    super(authenticationManager);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req,
                                  HttpServletResponse res,
                                  FilterChain chain) throws IOException, ServletException{
                                    
    String header = req.getHeader(SecurityConstants.HEADER_STRING);
    //caso o headerstring for null ou o prefixo seja diferente eu retorno nada e nao valido
    if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
      chain.doFilter(req, res);
      return;
    }

    UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

    SecurityContextHolder.getContext().setAuthentication(authentication);
    chain.doFilter(req, res);
  }

  private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {

    String token = request.getHeader(SecurityConstants.HEADER_STRING);
    if (token == null) { 
      return null;
    }

    //Parse the token
    String user = JWT.require(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()))
      .build()
      //Removo o prefixo
      .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""))
      //retorno o json do usuario, mas poderia retornar muito mais informacoes
      .getSubject();

    if (user != null) {
      //nao preciso das credencias pq a senha do user nao é salva no token
      return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
    }

    return null;
      
  }
}
