package law.ilovelaw;

import law.ilovelaw.models.Roles;
import law.ilovelaw.models.RolesEnum;
import law.ilovelaw.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
public class Initializer {

    @Autowired
    private RoleRepository roleRepository;

    @PostConstruct
    public void init() {
        if (roleRepository.findByName(RolesEnum.ADMIN).isEmpty()) {
            Roles admin = new Roles();
            admin.setId(1L);
            admin.setName(RolesEnum.ADMIN);
            roleRepository.save(admin);
        }

        if (roleRepository.findByName(RolesEnum.BASIC_USER).isEmpty()) {
            Roles basicUser = new Roles();
            basicUser.setId(2L);
            basicUser.setName(RolesEnum.BASIC_USER);
            roleRepository.save(basicUser);
        }

        if (roleRepository.findByName(RolesEnum.PREMIUM_USER).isEmpty()) {
            Roles premiumUser = new Roles();
            premiumUser.setId(3L);
            premiumUser.setName(RolesEnum.PREMIUM_USER);
            roleRepository.save(premiumUser);
        }
    }

}
