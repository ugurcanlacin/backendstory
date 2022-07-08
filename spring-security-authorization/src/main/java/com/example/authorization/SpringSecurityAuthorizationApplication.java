package com.example.authorization;

import com.example.authorization.JwtUtil;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.PostConstruct;
import javax.annotation.security.RolesAllowed;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@SpringBootApplication
public class SpringSecurityAuthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityAuthorizationApplication.class, args);
    }

    // Creating a bean for password encryption
    @Bean
    public BCryptPasswordEncoder getBCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

@RestController
class BasicController {
    @Autowired
    private JwtUtil jwtUtil;

    // injecting authentication manager
    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("login")
    public ResponseEntity<String> login(@RequestBody LoginRequestDTO request) {
        // Creating UsernamePasswordAuthenticationToken object
        // to send it to authentication manager.
        // Attention! We used two parameters constructor.
        // It sets authentication false by doing this.setAuthenticated(false);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        // we let the manager do its job.
        authenticationManager.authenticate(token);
        // if there is no exception thrown from authentication manager,
        // we can generate a JWT token and give it to user.
        String jwt = jwtUtil.generate(request.getUsername());
        return ResponseEntity.ok(jwt);
    }

    @GetMapping("/user/messages")
    @RolesAllowed("ROLE_USER")
    public ResponseEntity<String> getUserMessages(){
        List<String> messages = new ArrayList<>(List.of("Hello", "World"));
        return ResponseEntity.ok(messages.toString());
    }

    @GetMapping("/admin/messages")
    @RolesAllowed("ROLE_ADMIN")
    public ResponseEntity<String> getAdminMessages(){
        List<String> messages = new ArrayList<>(List.of("Top", "Secret"));
        return ResponseEntity.ok(messages.toString());
    }
}

@Data
@NoArgsConstructor
class LoginRequestDTO {
    private String username;
    private String password;
}

/*
 * This is Spring Security configuration step
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = false, // enables Spring's Secured annotation.
        jsr250Enabled = true, // enables the JSR-250 standard java security annotations, like @RolesAllowed
        prePostEnabled = false) // enables Spring's PreAuthorize and PostAuthorize annotations
class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    // Custom filter
    @Autowired
    private JwtTokenFilter jwtTokenFilter;

    // Custom UserDetailsService
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public void configurePasswordEncoder(AuthenticationManagerBuilder builder) throws Exception {
        // adding custom UserDetailsService and encryption bean to Authentication Manager
        builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Bean
    public AuthenticationManager getAuthenticationManager() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // disabling csrf since we won't use form login
                .csrf().disable()
                // giving permission to every request for /login endpoint
                .authorizeRequests().antMatchers("/login").permitAll()
                // only ROLE_USER can access to /user/** endpoint pattern
                .and().authorizeRequests().antMatchers("/user/**").hasRole("USER")
                // only ROLE_ADMIN can access to /admin/** endpoint pattern
                .and().authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN")
                // for everything else, the user has to be authenticated
                .anyRequest().authenticated()
                // setting stateless session, because we choose to implement Rest API
                .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // adding the custom filter before UsernamePasswordAuthenticationFilter in the filter chain
        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
}

/*
 * Custom filter will run once per request. We add this to Filter Chain
 */
@Component
class JwtTokenFilter extends OncePerRequestFilter {
    // Simple JWT implementation
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserDetailsService userDetailsService;

    // Spring Security will call this method during filter chain execution
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        // trying to find Authorization header
        final String authorizationHeader = httpServletRequest.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.isEmpty() || !authorizationHeader.startsWith("Bearer")){
            // if Authorization header does not exist, then skip this filter
            // and continue to execute next filter class
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        final String token = authorizationHeader.split(" ")[1].trim();
        if (!jwtUtil.validate(token)) {
            // if token is not valid, then skip this filter
            // and continue to execute next filter class.
            // This means authentication is not successful since token is invalid.
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        // Authorization header exists, token is valid. So, we can authenticate.
        // We will get username from token and use it to get user details from UserDetailsService
        String username = jwtUtil.getUsername(token);
        UserDetails user = userDetailsService.loadUserByUsername(username);

        // initializing UsernamePasswordAuthenticationToken with its 3 parameter constructor
        // because it sets super.setAuthenticated(true); in that constructor.
        UsernamePasswordAuthenticationToken upassToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());
        upassToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

        // finally, give the authentication token to Spring Security Context
        SecurityContextHolder.getContext().setAuthentication(upassToken);

        // end of the method, so go for next filter class
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}

@Data
@Builder
class UserDTO {
    private String username;
    private String password;
    private String role;
}

/*
 * Custom UserDetailsService implementation
 */
@Service
class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
    // In memory user database
    private static final Map<String, UserDTO> users = new HashMap<>();

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    // Initializing user database
    @PostConstruct
    public void init() {
        UserDTO userDTO = UserDTO.builder()
                .username("martin")
                .password(passwordEncoder.encode("123"))
                .role("ROLE_USER")
                .build();
        users.put("martin", userDTO);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // This is where you should fetch the user from database.
        if (users.containsKey(username)) {
            UserDTO userDTO = users.get(username);
            return new User(userDTO.getUsername(), userDTO.getPassword(), Arrays.asList(new SimpleGrantedAuthority(userDTO.getRole())));
        }
        // if this is thrown, then we won't generate JWT token.
        throw new UsernameNotFoundException(username);
    }
}


