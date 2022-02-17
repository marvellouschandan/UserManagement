package com.epam;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.epam.models.AppUser;
import com.epam.models.Role;
import com.epam.services.AppUserService;

// https://github.com/chaofz/jquery-jwt-auth/blob/master/index.html

@SpringBootApplication
public class UserManagementApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserManagementApplication.class, args);
	}
	
	@Bean
	CommandLineRunner run(AppUserService appUserService) {
		return args -> {
			appUserService.saveRole(new Role(null, "ROLE_USER"));
			appUserService.saveRole(new Role(null, "ROLE_MANAGER"));
			appUserService.saveRole(new Role(null, "ROLE_ADMIN"));
			appUserService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
			
			appUserService.saveUser(new AppUser(null, "Chandan Kumar", "chandan", "1234", new ArrayList<>()));
			appUserService.saveUser(new AppUser(null, "Krishna Boyapati", "krishna", "1234", new ArrayList<>()));
			appUserService.saveUser(new AppUser(null, "Souvik Dutta", "souvik", "1234", new ArrayList<>()));
			appUserService.saveUser(new AppUser(null, "Muskan salampuria", "muskan", "1234", new ArrayList<>()));
			
			appUserService.addRoleToUser("chandan", "ROLE_USER");
			appUserService.addRoleToUser("chandan", "ROLE_ADMIN");
			appUserService.addRoleToUser("chandan", "ROLE_SUPER_ADMIN");
			appUserService.addRoleToUser("krishna", "ROLE_ADMIN");
			appUserService.addRoleToUser("souvik", "ROLE_MANAGER");
			appUserService.addRoleToUser("muskan", "ROLE_USER");
		};	
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
