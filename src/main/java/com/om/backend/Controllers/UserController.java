package com.om.backend.Controllers;

import com.om.backend.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/get-ids-by-phone-numbers")
    public ResponseEntity<List<Long>> getListofIdsByPhoneNumbers(@RequestBody List<String> phoneNumbers){
        return userService.getUserIdsByPhoneNumbers(phoneNumbers);
    }

    @PostMapping("/get-id-by-phone-numbers")
    public ResponseEntity<Long> getUseridByPhoneNumber(@RequestBody String phoneNumber){
        return userService.getUserIdByPhoneNumber(phoneNumber);
    }

    @PostMapping("/get-phone-number-by-id")
    public ResponseEntity<String> getPhoneNumberByUserID(@RequestBody Long id){
        return  userService.getPhoneNumberByUserID(id);
    }

    @PostMapping("/get-phone-numbers-by-ids")
    public ResponseEntity<List<String>> getPhoneNumbersById(@RequestBody List<Long> id){
        return  userService.getPhoneNumbersByIds(id);
    }

    @PostMapping("/users/get-name-by-id")
    public String getUserById(@RequestBody Long id){
        return userService.getUserById(id);
    }
}
