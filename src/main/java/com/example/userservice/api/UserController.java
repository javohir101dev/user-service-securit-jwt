package com.example.userservice.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.userservice.domain.Role;
import com.example.userservice.domain.User;
import com.example.userservice.jwt.JwtProvider;
import com.example.userservice.service.UserService;
import com.example.userservice.utils.TokenHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {
    private final UserService userService;
    private final TokenHelper tokenHelper;
    private final JwtProvider jwtProvider;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> userList = userService.getAllUsers();
        return ResponseEntity.ok(userList);
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        String currentUriString = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/user/save").toUriString();
        URI location = URI.create(currentUriString);
        return ResponseEntity.created(location).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        String currentUriString = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/role/save").toUriString();
        URI location = URI.create(currentUriString);
        return ResponseEntity.created(location).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refreshTokenFromRequest = authorizationHeader.substring(7);
                JWTVerifier verifier = JWT.require(tokenHelper.getRefreshAlgorithm()).build();
                DecodedJWT verify = verifier.verify(refreshTokenFromRequest);
                String username = verify.getSubject();
                User user = userService.getUserByUsername(username);
                Collection<SimpleGrantedAuthority> authorities
                        = user.getRoles().stream().map(r -> new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList());
                org.springframework.security.core.userdetails.User springUser = new org.springframework.security.core.userdetails.User(
                        username, user.getPassword(), authorities);
                String accessToken = jwtProvider.accessToken(request, springUser);
                Map<String, String> error = new HashMap<>();
                error.put("access_token", accessToken);
                error.put("refresh_token", refreshTokenFromRequest);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            } catch (Exception e) {
                response.setHeader("error", e.getMessage());
                response.setStatus(HttpStatus.FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error", e.getMessage());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
}

@Data
class RoleToUserForm{
    private String username;
    private String roleName;
}
