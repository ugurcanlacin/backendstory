package com.backendstory.authentication;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class Scenario5 {

    public static void main(String[] args) {
        SpringApplication.run(Scenario5.class, args);
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

    @GetMapping("/hello")
    public ResponseEntity<String> get(){
        return ResponseEntity.ok("Hello");
    }
}

@Data
@NoArgsConstructor
class LoginRequestDTO {
    private String username;
    private String password;
}

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenFilter jwtTokenFilter;

    // Injecting JWT custom authentication provider
    @Autowired
    JwtAuthenticationProvider customAuthenticationProvider;

    // Injecting Google custom authentication provider
    @Autowired
    GoogleCloudAuthenticationProvider googleCloudAuthenticationProvider;

    @Bean
    public AuthenticationManager getAuthenticationManager() throws Exception {
        return super.authenticationManagerBean();
    }

    // adding our custom authentication providers
    // authentication manager will call these custom provider's
    // authenticate methods from now on.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(customAuthenticationProvider)
                .authenticationProvider(googleCloudAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // disabling csrf since we won't use form login
                .csrf().disable()

                // giving every permission to every request for /login endpoint
                .authorizeRequests().antMatchers("/login").permitAll()
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
        String username = jwtUtil.getUsername(token);
        // initializing UsernamePasswordAuthenticationToken with its 3 parameter constructor
        // because it sets super.setAuthenticated(true); in that constructor.
        UsernamePasswordAuthenticationToken upassToken = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        upassToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
        // finally, give the authentication token to Spring Security Context
        SecurityContextHolder.getContext().setAuthentication(upassToken);

        // end of the method, so go for next filter class
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}

@Component
class JwtAuthenticationProvider implements AuthenticationProvider {
    // Injecting available encryption bean
    @Autowired
    private PasswordEncoder passwordEncoder;

    // Injecting our custom UserDetailsService implementation
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // In BasicController.login() method, we call authenticationManager.authenticate(token)
        // Then, Authentication Manager calls AuthenticationProvider's authenticate method.
        // Since JwtAuthenticationProvider is our custom authentication provider,
        // this method will be executed.
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());

        // Fetching user as wrapped with UserDetails object
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // If user is not null, then we check if password matches
        if (userDetails != null){
            if (passwordEncoder.matches(password, userDetails.getPassword())){
                // if it matches, then we can initialize UsernamePasswordAuthenticationToken.
                // Attention! We used its 3 parameters constructor.
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
                return authenticationToken;
            }
        }
        throw new BadCredentialsException("Error!!");
    }

    // Authentication Manager checks if the token is supported by this filter
    // to avoid unnecessary checks.
    @Override
    public boolean supports(Class<?> authenticationType) {
        return UsernamePasswordAuthenticationToken.class.equals(authenticationType);
    }
}

/*
 * Custom UserDetailsService implementation
 */
@Service
class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // This is where you should fetch the user from database.
        // We keep it simple to focus on authentication flow.
        Map<String, String> users = new HashMap<>();
        users.put("martin", passwordEncoder.encode("123"));
        if (users.containsKey(username))
            return new User(username, users.get(username), new ArrayList<>());
        // if this is thrown, then we won't generate JWT token.
        throw new UsernameNotFoundException(username);
    }
}

@Component
class GoogleCloudAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());

        // We fetch user from Google API "in theory"
        User user = getUserFromGoogleCloud(username, password);
        if (user != null) {
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, password, user.getAuthorities());
            return authenticationToken;
        }
        throw new BadCredentialsException("Error!!");
    }

    // Let's assume Google API will return the user in this method.
    private User getUserFromGoogleCloud(String username, String password) {
        Map<String, String> users = new HashMap<>();
        users.put("ugur", "123");
        if (users.get(username) != null){
            return new User(username, password, Collections.emptyList());
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return UsernamePasswordAuthenticationToken.class.equals(authenticationType);
    }

}