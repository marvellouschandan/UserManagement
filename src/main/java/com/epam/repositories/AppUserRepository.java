package com.epam.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.epam.models.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long>{
	AppUser findByUsername(String username);
}
