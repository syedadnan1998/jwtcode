package com.example.demo.security;

import java.util.Date;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtProvider {


    private final String ROLES_KEY = "roles";

    private JwtParser parser;

    private String secretKey;
    private long validityInMilliseconds;
    
    public JwtProvider(@Value("${security.jwt.token.secret-key}") String secretKey,
    					@Value("${security.jwt.token.expiration}") long validityInMs) {
    	this.secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    	this.validityInMilliseconds = validityInMs;
    }
    
    public String createToken(String username, List<String> roles) {
    	Claims claims = Jwts.claims();
    	claims.setSubject(username);
    	List<GrantedAuthority> roleList = roles.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
    	claims.put(ROLES_KEY, roleList);
    	
    	Date validityDate = new Date((new Date()).getTime() + this.validityInMilliseconds);
    	
    	return Jwts.builder()
    			.setClaims(claims)
    			.setIssuedAt(new Date())
    			.setExpiration(validityDate)
    			.signWith(SignatureAlgorithm.HS256, secretKey)
    			.compact();
    }
    
    public boolean isValidToken(String inputToken) {
    	try {
    		Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(inputToken).getBody();
    		return true;
    	} catch (Exception ex) {
    		ex.printStackTrace();
    		return false;
    	}
    }
    
    public String getUserName(String token) {
		return Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(token).getBody().getSubject();    	
    }
    
    public List<GrantedAuthority> getRoles(String token) {
    	List<Map<String, String>> roleClaims = Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(token).getBody().get(ROLES_KEY, List.class);
    	
    	return roleClaims.stream().map(roleClaim -> {
    		return new SimpleGrantedAuthority(roleClaim.get("authority"));
    	}).collect(Collectors.toList());
    }
}
