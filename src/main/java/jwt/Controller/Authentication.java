package jwt.Controller;

import jwt.Entities.User;
import jwt.Service.UserService;
import jwt.Utility.JwtUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Authentication {

    @Autowired
    private UserService service;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtility jwtUtil;


    @PostMapping("/register")
    public User register() {
        return service.createUser();

    }

    @GetMapping("/test")
    public String test() {
        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(authentication.getCredentials());
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        System.out.println(principal.getUsername());
        System.out.println(authentication.isAuthenticated());
        return "okay";

    }

    @PostMapping("/login")
    public ResponseEntity<?> login() {
        try {
            org.springframework.security.core.Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("vivekpal@gmail.com", "password"));
            if (authenticate.isAuthenticated()){
                System.out.println("authenticated successful");
            }
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
        final String token = jwtUtil.generateToken("vivekpal@gmail.com");
        System.out.println(token);
        return ResponseEntity.ok(token);
    }

}
