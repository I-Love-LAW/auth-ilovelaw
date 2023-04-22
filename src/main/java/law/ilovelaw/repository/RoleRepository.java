package law.ilovelaw.repository;

import law.ilovelaw.models.Roles;
import law.ilovelaw.models.RolesEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Roles, Long> {
    Optional<Roles> findByName(RolesEnum name);
}