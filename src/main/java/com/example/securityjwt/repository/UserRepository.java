package com.example.securityjwt.repository;

import com.example.securityjwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {
    @Query(value = "select u from User u where u.userName = ?1")
    User findUserByUserName(String userName);

    @Query(value = "select u from User u where u.refreshToken = ?1")
    User findUserByRefreshToken(String refreshToken);
}
