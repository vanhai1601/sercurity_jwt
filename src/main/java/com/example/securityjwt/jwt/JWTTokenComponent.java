package com.example.securityjwt.jwt;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;

@Component
public class JWTTokenComponent {

	private final String secret = "sdghsdghsgd";
	private final long tokenLifetime = 120L;
	private final long refreshTokenLifetime = 1000L;

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private boolean isTokenExpired(String token) {
		Date date = getExpirationFromToken(token);
		return date.before(new Date());
	}

	public String doGenerateRefreshToken(UserDetails user) {
		Date now = new Date();
		return Jwts.builder()
				.setSubject(user.getUsername())
				.setIssuedAt(now)
				.setExpiration(new Date(now.getTime() + refreshTokenLifetime * 1000))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	private String doGenerateToken(UserDetails user) {
		Date now = new Date();
		Map<String, Object> claims = new HashMap<>();
		Collection<? extends GrantedAuthority> roles = user.getAuthorities();

		if (roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			claims.put("isAdmin", true);
		}
		if (roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			claims.put("isUser", true);
		}
		return Jwts.builder()
				.setSubject(user.getUsername())
				.setIssuedAt(now)
				.setExpiration(new Date(now.getTime() + tokenLifetime * 1000))
				.addClaims(claims)
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public String getUserNameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getExpirationFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public List<SimpleGrantedAuthority> getRolesFromToken(String token) {
		Claims claims = getAllClaimsFromToken(token);
		List<SimpleGrantedAuthority> roles = new ArrayList<>();

		Boolean isAdmin = claims.get("isAdmin", Boolean.class);
		Boolean isUser = claims.get("isUser", Boolean.class);

		if (isAdmin != null && isAdmin) {
			roles.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
		}

		if (isUser != null && isAdmin) {
			roles.add(new SimpleGrantedAuthority("ROLE_USER"));
		}
		return roles;
	}

	public String generateToken(UserDetails user) {
		return doGenerateToken(user);
	}

	public boolean validateToken(String token, UserDetails user) {
		String userName = getUserNameFromToken(token);
		return userName.equals(user.getUsername()) && !isTokenExpired(token);
	}
}
