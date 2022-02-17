package com.epam.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import javax.transaction.Transactional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.epam.models.AppUser;
import com.epam.models.Role;
import com.epam.repositories.AppUserRepository;
import com.epam.repositories.RoleRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor /* Autowiring not required */
@Transactional
@Slf4j
public class AppUserServiceImpl implements AppUserService, UserDetailsService{
	private final AppUserRepository appUserRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;
	
	/* This came from UserDetailsService */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser user = appUserRepository.findByUsername(username);
		if (Objects.isNull(user)) {
			log.error("Username {} not found in the database!", username);
			throw new UsernameNotFoundException(String.format("Username {} not found in the database!", username));
		}else {
			log.info("Username {} found in the database!", username);
		}
		
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
	}

	@Override
	public AppUser saveUser(AppUser user) {
		log.info("Saving new user {} to database!", user.getUsername());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return appUserRepository.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving new role {} to database!", role.getName());
		return roleRepository.save(role);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		AppUser user = appUserRepository.findByUsername(username);
		Role role = roleRepository.findByName(roleName);
		log.info("Adding role {} to user {}", roleName, username);
		user.getRoles().add(role);
	}

	@Override
	public AppUser getUser(String username) {
		log.info("Fetching user {}", username);
		return appUserRepository.findByUsername(username);
	}

	@Override
	public List<AppUser> getUsers() {
		/* Better use pagination here, as getting millions of users will cause
		 * heavy load to the backend server */
		log.info("Fetching all users");
		return appUserRepository.findAll();
	}


}
