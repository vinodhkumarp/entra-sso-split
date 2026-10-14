package com.example.entrasso.login;

import com.example.entrasso.sso.EnableEntraSso;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Starts the login API, which validates the Entra token and returns the caller's roles. */
@SpringBootApplication
@EnableEntraSso
public class LoginApiApplication {

  /** Launches the API and its embedded web server. */
  public static void main(String[] args) {
    SpringApplication.run(LoginApiApplication.class, args);
  }
}
