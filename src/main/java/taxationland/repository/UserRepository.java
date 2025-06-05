package taxationland.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import taxationland.model.User;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    
    // Búsqueda por campos individuales
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    
    // Búsqueda combinada optimizada
    @Query("SELECT u FROM User u WHERE u.username = :credential OR u.email = :credential")
    Optional<User> findByUsernameOrEmail(@Param("credential") String credential);
    
    // Verificación de existencia
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
    
    // Opcional: Método combinado de verificación
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.username = :credential OR u.email = :credential")
    Boolean existsByUsernameOrEmail(@Param("credential") String credential);
}