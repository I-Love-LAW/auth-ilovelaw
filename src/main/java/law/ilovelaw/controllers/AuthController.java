package law.ilovelaw.controllers;

import law.ilovelaw.exception.TokenRefreshException;
import law.ilovelaw.models.RefreshToken;
import law.ilovelaw.models.User;
import law.ilovelaw.payload.request.LoginRequest;
import law.ilovelaw.payload.request.LogoutRequest;
import law.ilovelaw.payload.request.SignupRequest;
import law.ilovelaw.payload.request.TokenRefreshRequest;
import law.ilovelaw.payload.response.JwtResponse;
import law.ilovelaw.payload.response.MessageResponse;
import law.ilovelaw.payload.response.TokenRefreshResponse;
import law.ilovelaw.security.jwt.JwtUtils;
import law.ilovelaw.security.services.RefreshTokenService;
import law.ilovelaw.security.services.UserDetailsImpl;
import law.ilovelaw.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserService userService;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication;

        try {
            authentication= authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad Credentials: Unauthorized");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String accessToken = jwtUtils.generateJwtToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(new JwtResponse(accessToken, refreshToken.getToken(),
                userDetails.getUsername(), roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userService.cekExistsUserByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username is already taken!"));
        }

        userService.createUser(signUpRequest);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefresh();
        String token;

        try {
            Optional<RefreshToken> optionalRefreshToken = refreshTokenService.findByToken(requestRefreshToken);
            if (optionalRefreshToken.isPresent()) {
                RefreshToken refreshToken = refreshTokenService.verifyExpiration(optionalRefreshToken.get());
                User user = refreshToken.getUser();
                token = jwtUtils.generateTokenFromUsername(user.getUsername());
            } else {
                throw new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!");
            }
        } catch (TokenRefreshException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }

        return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(@Valid @RequestBody LogoutRequest logoutRequest) {
        try {
            User user = userService.getUserByUsername(logoutRequest.getUsername());
            String userId = user.getId();
            refreshTokenService.deleteByUserId(userId);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }

        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }

}