package com.example.demo.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.demo.security.JwtProvider;

import static org.springframework.security.core.userdetails.User.withUsername;

@Component
public class CustomUserDetailsService implements UserDetailsService {
	
	private static final String DEFAULT_ROLE = "ROLE_USER";
	
	@Autowired
	private JwtProvider jwtProvider;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String password = (new BCryptPasswordEncoder(32)).encode("letmein");
		
		List<GrantedAuthority> authorities = Arrays.asList(DEFAULT_ROLE).stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
		
		return User.withUsername(username)
				.password(password)
				.authorities(authorities)
				.accountExpired(false)
				.accountLocked(false)
				.credentialsExpired(false)
				.disabled(false)
				.build();
	}
	
	public Optional<UserDetails> getUserByJwtToken(String token) {
		
		if (jwtProvider.isValidToken(token)) {
			Optional.of(
					User.withUsername(jwtProvider.getUserName(token))
					.password("")
					.authorities(jwtProvider.getRoles(token))
					.accountExpired(false)
					.accountLocked(false)
					.credentialsExpired(false)
					.disabled(false)
					.build()
					);
		}
		
		return Optional.empty();
	}

}
