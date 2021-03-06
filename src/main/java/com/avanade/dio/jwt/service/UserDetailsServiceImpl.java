package com.avanade.dio.jwt.service;

import java.util.Collection;
import java.util.Collections;

import com.avanade.dio.jwt.data.UserData;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class UserDetailsServiceImpl implements UserDetailsService{

  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  public UserDetailsServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
  }

  @Override
  public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
    
    UserData user = findUser(userName);
    if (user == null) {
      throw new UsernameNotFoundException("Usuario não encontrado: " + userName);
    }

    return new User(user.getUserName(), user.getPassword(), Collections.emptyList());
  } 

  //findUser poderia estar buscando o usuario em qualquer lugar, exem: arquivo, bd
  private UserData findUser(String username) {
    
    UserData user = new UserData();
    user.setUserName("admin");
    user.setPassword(bCryptPasswordEncoder.encode("nimda"));

    return user;
  }
}
