package com.epam.services;

import java.util.List;

import com.epam.models.AppUser;
import com.epam.models.Role;

public interface AppUserService {
	AppUser saveUser(AppUser user);
	Role saveRole(Role role);
	void addRoleToUser(String username, String role);
	AppUser getUser(String username);
	List<AppUser> getUsers();
}
