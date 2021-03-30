package com.enigma.jwt.repository;

import com.enigma.jwt.models.ERole;
import com.enigma.jwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
