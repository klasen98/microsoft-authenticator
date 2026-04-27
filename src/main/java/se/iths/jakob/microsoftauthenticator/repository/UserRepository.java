package se.iths.jakob.microsoftauthenticator.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import se.iths.jakob.microsoftauthenticator.model.AppUser;

@Repository
public interface UserRepository extends JpaRepository<AppUser, Long> {

    AppUser findByUsername(String username);

}
