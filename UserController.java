package com.example.demo.controller;

import java.util.Map;

import javax.annotation.security.RolesAllowed;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.LoginDto;
import com.example.demo.service.UserService;

@RestController
@RequestMapping(value = "/api")
public class UserController {
	@Autowired
	private UserService userService;
	
	@PostMapping("/signin")
	public String signin(@RequestBody @Valid LoginDto loginDto) {
		return userService.signin(loginDto);
	}
	
	@GetMapping("/userDetails")
//	@PreAuthorize(value = "hasRole('ROLE_USER') or hasRole('ADMIN')")
	@RolesAllowed({"ROLE_USER", "ADMIN"})
	public Map<String, String> getUserDetails(HttpServletRequest request) {
		return userService.getUserDetails(request);
	}
}
