package law.ilovelaw.controllers;

import law.ilovelaw.models.User;
import law.ilovelaw.payload.response.UserResponse;
import law.ilovelaw.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/{username}")
    public ResponseEntity<?> getNameByUsername(@PathVariable String username) {
        UserResponse userResponse;

        try {
            User user = userService.getUserByUsername(username);
            userResponse = new UserResponse(user.getId(), user.getName());
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad Credentials: Unauthorized");
        }

        return ResponseEntity.ok(userResponse);
    }

}
