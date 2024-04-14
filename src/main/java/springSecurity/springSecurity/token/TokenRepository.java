package springSecurity.springSecurity.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    //Getting all valid tokens for the user
    @Query("""
    select t from Token t inner join User u on t.user.id = u.id
    where u.id = :userId and (t.expired = false or t.revoked = false)
    """)
    List<Token> findAllValidTokensByUser(Integer userId);

    //Finding token from database
    Optional<Token> findByToken(String token);
}
