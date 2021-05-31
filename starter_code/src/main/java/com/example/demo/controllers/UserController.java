package com.example.demo.controllers;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;

// slf4j and log4j
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

// log4j (needs separate property file)
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {

	// create a logger object for the current class
//	public Logger logger = LoggerFactory.getLogger(UserController.class);

	// alternative using log4j
	public Logger logger = LogManager.getLogger(UserController.class);
	static {
		// PropertiesConfigurator is used to configure logger from properties file
		PropertyConfigurator.configure(UserController.class.getClassLoader().getResource("log4j.properties"));
	}

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private CartRepository cartRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/id/{id}")
	public ResponseEntity<User> findById(@PathVariable Long id) {
		return ResponseEntity.of(userRepository.findById(id));
	}
	
	@GetMapping("/{username}")
	public ResponseEntity<User> findByUserName(@PathVariable String username) {
		User user = userRepository.findByUsername(username);
		return user == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(user);
	}
	
	@PostMapping("/create")
	public ResponseEntity<User> createUser(@RequestBody CreateUserRequest createUserRequest) {
		User user = new User();
		user.setUsername(createUserRequest.getUsername());
		logger.info("User name set with " + createUserRequest.getUsername());

		Cart cart = new Cart();
		final Cart cart1 = cartRepository.save(cart);
		boolean b = logger.isDebugEnabled();
		logger.warn("Cart saved with ID " + cart1.getId());
		user.setCart(cart);

		logger.trace("this is a trace log");
		logger.debug("this is a debug log");
		logger.info("this is an info log");
		logger.warn("this is a warning log");
		logger.error("this is an error log");


		// only for log4J
		logger.fatal("this is a fatal log");

		// add security
		if(createUserRequest.getPassword().length()<7 ||
			!createUserRequest.getPassword().equals(createUserRequest.getConfirmPassword())) {
			return ResponseEntity.badRequest().build();
		}

		// assign the encoded password to user using the bean loaded in the main application
		// in com.example.demo folder
		user.setPassword(bCryptPasswordEncoder.encode(createUserRequest.getPassword()));

		userRepository.save(user);
		return ResponseEntity.ok(user);
	}
	
}
