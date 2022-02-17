package com.epam.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.epam.models.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{
	Role findByName(String name);
}
