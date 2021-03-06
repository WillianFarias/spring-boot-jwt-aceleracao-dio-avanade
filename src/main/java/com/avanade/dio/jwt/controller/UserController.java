package com.avanade.dio.jwt.controller;

import java.util.List;

import com.avanade.dio.jwt.data.UserData;
import com.avanade.dio.jwt.service.UserDetailsServiceImpl;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

  private final UserDetailsServiceImpl userDetailsService;

  public UserController(UserDetailsServiceImpl userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  @RequestMapping("/all-users")
  public List<UserData> listAllUsers() {
    return userDetailsService.listUsers();
  }
  
}
