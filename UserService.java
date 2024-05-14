package com.example.demo.service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import com.example.demo.dto.LoginDto;
import com.example.demo.security.JwtProvider;

@Service
public class UserService {

	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	JwtProvider jwtProvider;
	
	
	public String signin(LoginDto loginDto) {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
			return jwtProvider.createToken(loginDto.getUsername(), Arrays.asList("ADMIN"));
		} catch (AuthenticationException ex) {
			ex.printStackTrace();
		}
		return "failed to login";
	}
	
	public Map<String, String> getUserDetails(HttpServletRequest request) {
		Map<String, String> userMap = new HashMap<String, String>();
		String token = request.getHeader("x-auth-token");
		userMap.put("userName", jwtProvider.getUserName(token));
		userMap.put("roles", jwtProvider.getRoles(token).toString());
		return userMap;
	}
	
}
