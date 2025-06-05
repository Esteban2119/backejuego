package taxationland.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import taxationland.dto.*;
import taxationland.model.*;
import taxationland.repository.*;
import taxationland.security.jwt.JwtUtils;
import taxationland.security.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            // Búsqueda optimizada
            String credential = loginRequest.getUsernameOrEmail().trim();
            User user = userRepository.findByUsernameOrEmail(credential)
                    .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));

            // Verificación mejorada de contraseña
            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Credenciales inválidas");
            }

            // Verificación de roles mejorada
            if (user.getRoles() == null || user.getRoles().isEmpty()) {
                logger.warn("Usuario sin roles: {}", user.getUsername());
                throw new RuntimeException("Configuración de usuario incompleta");
            }

            // Autenticación
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // Generación de token
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            // Construcción de respuesta
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(new JwtResponse(
                    jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));

        } catch (BadCredentialsException e) {
            logger.warn("Intento de login fallido para: {}", loginRequest.getUsernameOrEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Credenciales inválidas"));
        } catch (Exception e) {
            logger.error("Error en autenticación: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error en el servidor"));
        }
    }

    /**
     * Registra un nuevo usuario con rol ROLE_USER
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        try {
            // Validación mejorada
            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                return ResponseEntity.badRequest()
                        .body(new MessageResponse("Error: El nombre de usuario ya está en uso"));
            }

            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ResponseEntity.badRequest()
                        .body(new MessageResponse("Error: El email ya está en uso"));
            }

            // Crear nuevo usuario
            User user = new User(
                    signUpRequest.getUsername(),
                    signUpRequest.getEmail(),
                    passwordEncoder.encode(signUpRequest.getPassword())
            );

            // Asignar rol
            Set<Role> roles = new HashSet<>();
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(userRole);
            user.setRoles(roles);

            userRepository.save(user);

            return ResponseEntity.ok(new MessageResponse("Usuario registrado exitosamente"));

        } catch (Exception e) {
            logger.error("Error en registro: ", e);
            return ResponseEntity.internalServerError()
                    .body(new MessageResponse("Error interno del servidor"));
        }
    }
}
