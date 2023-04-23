package law.ilovelaw.services;

import law.ilovelaw.models.Roles;

import java.util.Set;

public interface RolesService {
    Set<Roles> assignRoles(Set<String> strRoles);
}
