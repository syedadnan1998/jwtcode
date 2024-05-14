package com.example.demo.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.example.demo.service.CustomUserDetailsService;


public class JwtFilter extends GenericFilterBean {
	
	CustomUserDetailsService userDetailsService;
	
	public JwtFilter(CustomUserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest servRequest = (HttpServletRequest) request;
		String token = servRequest.getHeader("x-auth-token");
		if (token != null && !token.isEmpty()) {
			userDetailsService.getUserByJwtToken(token).ifPresent(userDetails -> {
				SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "", userDetails.getAuthorities()));
			});
		}
		
		
		chain.doFilter(request, response);
	}
	
}
