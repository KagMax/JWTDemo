package pl.sda.jwtdemo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import pl.sda.jwtdemo.dto.LoginUserDto;
import pl.sda.jwtdemo.dto.RegisterUserDto;
import pl.sda.jwtdemo.entities.User;
import pl.sda.jwtdemo.services.AuthenticationService;
import pl.sda.jwtdemo.services.JwtService;

@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private final JwtService jwtService;

    public AuthenticationController(AuthenticationService authenticationService, JwtService jwtService) {
        this.authenticationService = authenticationService;
        this.jwtService = jwtService;
    }

    // register
    @PostMapping("/auth/register")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
        User registerUser = authenticationService.register(registerUserDto);

        return ResponseEntity.ok(registerUser);
    }

    // login
    @PostMapping("/auth/login")
    public ResponseEntity<Object> login(@RequestBody LoginUserDto loginUserDto) {
        User user = authenticationService.login(loginUserDto);

        String token = jwtService.generateToken(user);

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken(token);
        loginResponse.setExpiresIn(jwtService.getExpiration(token));

        return ResponseEntity.ok(loginResponse);
    }
}
