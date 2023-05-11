package law.ilovelaw.services;

import law.ilovelaw.models.Roles;
import law.ilovelaw.models.RolesEnum;
import law.ilovelaw.models.User;
import law.ilovelaw.payload.request.SignupRequest;
import law.ilovelaw.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;

    @Autowired
    RolesService rolesService;

    @Autowired
    PasswordEncoder encoder;

    @Override
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
    }

    @Override
    public Boolean cekExistsUserByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    @Override
    public void createUser(SignupRequest signUpRequest) {
        // Create new user's account
        User user = new User();
        user.setName(signUpRequest.getName());
        user.setUsername(signUpRequest.getUsername());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Roles> roles = rolesService.assignRoles(strRoles);

        user.setRoles(roles);
        userRepository.save(user);
    }

    @Override
    public void updateProfileUser(String username, String name) {
        Optional<User> optionalUser = userRepository.findByUsername(username);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.setName(name);
            userRepository.save(user);
        } else {
            throw new UsernameNotFoundException("User Not Found with username: " + username);
        }

    }

    @Override
    public Boolean upgradeUserMembership(String username) {
        Optional<User> optionalUser = userRepository.findByUsername(username);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            Set<String> rolesName = new HashSet<>();
            for (Roles role : user.getRoles()) {
                if (role.getName().equals(RolesEnum.PREMIUM_USER)) {
                    return false;
                }
                else if (role.getName().equals(RolesEnum.BASIC_USER)) {
                    continue;
                }
                rolesName.add(role.getName().name());
            }
            rolesName.add("PREMIUM");
            user.setRoles(rolesService.assignRoles(rolesName));
            userRepository.save(user);
            return true;

        } else {
            throw new UsernameNotFoundException("User Not Found with username: " + username);
        }
    }

    @Override
    public Boolean cekUserConvertEligibility(String username, int totalConversion) {
        Optional<User> optionalUser = userRepository.findByUsername(username);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            for (Roles role : user.getRoles()) {
                if (role.getName().equals(RolesEnum.BASIC_USER)) {
                    return totalConversion < 5;
                } else if (role.getName().equals(RolesEnum.PREMIUM_USER)) {
                    return true;
                }
            }
            return true;

        } else {
            throw new UsernameNotFoundException("User Not Found with username: " + username);
        }
    }
}
