package com.Ahmed.book.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthenticationRequest {

    @Email(message = "Email is in a wrong Format (***@****.com")
    private String email;
    @NotEmpty(message = "Firstname can't be Empty")
    @NotBlank(message = "Firstname can't be Empty")
    @Size(min = 8, message = "Password shouldn't be less than 8 chars")
    private String password;
}
