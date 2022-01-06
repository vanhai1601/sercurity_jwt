package com.example.securityjwt.controller;

import com.example.securityjwt.dto.request.AuthenticationRequestDTO;
import com.example.securityjwt.dto.request.UserRequest;
import com.example.securityjwt.dto.response.AuthenticationResponseDTO;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.jwt.JWTTokenComponent;
import com.example.securityjwt.repository.UserRepository;
import com.example.securityjwt.service.JWTUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.List;


@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTUserDetailsService jwtUserDetailsService;
    @Autowired
    private JWTTokenComponent jwtTokenComponent;


    @PostMapping("/register")
    public User registerUser(@RequestBody UserRequest userRequest) {
        User user = new User();
        user.setUserName(userRequest.getUserName());
        user.setRolesId(userRequest.getRolesId());
        user.setEmail(userRequest.getEmail());
        user.setPhoneNumber(userRequest.getPhoneNumber());
        user.setStatus(1);
        user.setPassword(userRequest.getPassword());
        encryptPassword(user);
        userRepository.save(user);
        return user;
    }

    @PostMapping("/login")
    public AuthenticationResponseDTO login(@RequestBody AuthenticationRequestDTO dto) {
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(dto.getUserName(), dto.getPassword()));
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(dto.getUserName());
        String token = jwtTokenComponent.generateToken(userDetails);
        String refreshToken = jwtTokenComponent.doGenerateRefreshToken(userDetails);
        String userName = jwtTokenComponent.getUserNameFromToken(token);
        User user = userRepository.findUserByUserName(userName);
        user.setToken(token);
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        AuthenticationResponseDTO authenticationResponseDTO = new AuthenticationResponseDTO();
        authenticationResponseDTO.setJwtToken(token);
        authenticationResponseDTO.setRefreshToken(refreshToken);
        return authenticationResponseDTO;
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestParam(value = "refreshToken") String refreshToken) throws ServletException, IOException {
        User user = userRepository.findUserByRefreshToken(refreshToken);
        try {
            if (user != null) {
                UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(user.getUserName());
                Boolean check = jwtTokenComponent.validateToken(user.getToken(),userDetails);
                return ResponseEntity.ok("token chưa hết hiệu lực");
            } else {
                return ResponseEntity.badRequest().body("refreshtoken không đúng hoặc hết hiệu lực");
            }
        } catch (ExpiredJwtException ex) {
            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(user.getUserName());
            String token = jwtTokenComponent.generateToken(userDetails);
            user.setToken(token);
            userRepository.save(user);
            AuthenticationResponseDTO authenticationResponseDTO = new AuthenticationResponseDTO();
            authenticationResponseDTO.setJwtToken(token);
            authenticationResponseDTO.setRefreshToken(refreshToken);
            return ResponseEntity.ok(authenticationResponseDTO);
        }
    }

    @GetMapping("/all")
    @Secured("ROLE_ADMIN")
    public List<User> getListUser() {
        return userRepository.findAll();
    }

    private void encryptPassword(User user) {
        String rawPassword = user.getPassword();
        if (rawPassword != null) {
            user.setPassword(passwordEncoder.encode(rawPassword));
        }
    }


}
