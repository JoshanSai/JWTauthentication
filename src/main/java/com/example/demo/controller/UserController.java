package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.entity.AuthRequest;
import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.CustomerDetails;
import com.example.demo.util.JwtUtil;

@RestController
public class UserController {
	 @Autowired
	    private JwtUtil jwtUtil;
	    @Autowired
	    private AuthenticationManager authenticationManager;
	@Autowired
	public CustomerDetails cust;
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private UserRepository userRepository;


	
	@PostMapping("/add")
	public String addUser( @RequestBody User user)
	{
		String pwd= user.getPassword();
		 String encrptedPwd = passwordEncoder.encode(pwd);
		 user.setPassword(encrptedPwd);
		 userRepository.save(user);
		return "user Added Successfully";
		
	}
	@PreAuthorize("hasAuthority('admin')")
	@GetMapping("/admin")
	public String process3()
	{
		return "Admin details...........";
	}
	@PreAuthorize("hasAuthority('user') or hasAuthority('admin')")
	@GetMapping("/user")
	public String process4()
	{
		return "User details..........";
	}
	 @PostMapping("/authenticate")
	    public String generateToken(@RequestBody AuthRequest authRequest) throws Exception {
		 User user = userRepository.findByUsername(authRequest.getUserName());
		 
	        try {
	            authenticationManager.authenticate(
	                    new UsernamePasswordAuthenticationToken(authRequest.getUserName(), authRequest.getPassword())
	            );
	        } catch (Exception ex) {
	            throw new Exception("inavalid username/password");
	        }
	        return jwtUtil.generateToken(authRequest.getUserName(),user.getEmail());
	    }
	}
