package law.ilovelaw.services;

import law.ilovelaw.models.Roles;
import law.ilovelaw.models.RolesEnum;
import law.ilovelaw.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class RolesServiceImpl implements RolesService {
    @Autowired
    RoleRepository roleRepository;

    public Roles findByName(RolesEnum name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
    }

    @Override
    public Set<Roles> assignRoles(Set<String> strRoles) {
        Set<Roles> roles = new HashSet<>();

        if (strRoles == null) {
            Roles userRole = findByName(RolesEnum.BASIC_USER);
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "ADMIN" -> {
                        Roles adminRole = findByName(RolesEnum.ADMIN);
                        roles.add(adminRole);
                    }
                    case "PREMIUM" -> {
                        Roles userRole = findByName(RolesEnum.PREMIUM_USER);
                        roles.add(userRole);
                    }
                    default -> {
                        Roles userRole = findByName(RolesEnum.BASIC_USER);
                        roles.add(userRole);
                    }
                }
            });
        }

        return roles;
    }
}
