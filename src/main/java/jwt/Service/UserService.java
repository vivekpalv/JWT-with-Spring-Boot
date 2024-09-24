package jwt.Service;

import jwt.Entities.User;
import jwt.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User createUser(){
        User newUser = new User();
        newUser.setUsername("vivekpal@gmail.com");
        newUser.setPassword(passwordEncoder.encode("password"));
        newUser.setRole("ADMIN");

        User savedUser = userRepository.save(newUser);

        return savedUser;
    }

    public Optional<User> findByUsername(String username){
        return userRepository.findByUsername(username);
    }


}
