package com.avanade.dio.jwt.security;

import com.avanade.dio.jwt.service.UserDetailsServiceImpl;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
  
  private final UserDetailsServiceImpl userDetailsService;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  public WebSecurity(UserDetailsServiceImpl userDetailsService, 
  BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.userDetailsService = userDetailsService;
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    //define que a api pode ser requisitada por qlqer um, nao apenas por que esta
    //na mesma rede
    http.cors().and().csrf().disable().authorizeRequests()
      .antMatchers(HttpMethod.GET, SecurityConstants.STATUS_URL)
      .permitAll()
      .antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL)
      .permitAll()
      .anyRequest().authenticated();
  }

  @Override
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
  }

  @Bean
  //defininco que a requisicao para minha api pode vim de qlquer servidor
  CorsConfigurationSource corsConfigurationSource() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
    return source;
  }

}
