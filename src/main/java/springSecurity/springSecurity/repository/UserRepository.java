package springSecurity.springSecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import springSecurity.springSecurity.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
}
