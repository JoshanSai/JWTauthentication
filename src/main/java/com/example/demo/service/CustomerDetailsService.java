package com.example.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;

@Service
public class CustomerDetailsService implements UserDetailsService {
	
	@Autowired
	private UserRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println(username);
		User user = repository.findByUsername(username);
		CustomerDetails userDetails = null;
		if(user !=null)
		{
			userDetails = new CustomerDetails();
			userDetails.setUser(user);
				}
		else {
			throw new UsernameNotFoundException("user not exits with the name" + username);
		}
		
	
		return userDetails;
	}

}
