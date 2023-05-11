package law.ilovelaw.controllers;

import law.ilovelaw.models.User;
import law.ilovelaw.payload.request.UpdateRequest;
import law.ilovelaw.payload.response.MessageResponse;
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
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Bad Credentials: Unauthorized"));
        }

        return ResponseEntity.ok(userResponse);
    }

    @PutMapping("/update-profile")
    public ResponseEntity<?> updateProfileUser(@RequestBody UpdateRequest updateRequest) {

        try {
            userService.updateProfileUser(updateRequest.getUsername(), updateRequest.getName());
            return ResponseEntity.ok(new MessageResponse("User anda telah di-update"));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Bad Credentials: Unauthorized"));
        }

    }

}
