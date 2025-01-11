package com.Ahmed.book.handler;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

public enum BusinessErrorCodes {

    NO_CODE(0, NOT_IMPLEMENTED, "No Code"),
    INCORRECT_CURRENT_PASSWORD(300, BAD_REQUEST, "Current Password is incorrect"),
    NEW_PASSWORD_DOES_NOT_MATCH(301, BAD_REQUEST, "The New Password Doesn't Match"),
    ACCOUNT_LOCKED(302, FORBIDDEN, "User Account is Locked"),
    ACCOUNT_DISABLED(303,FORBIDDEN, "User Account is Disabled"),
    BAD_CREDENTIALS(304, FORBIDDEN, " Login and / or password is incorrect")


    ;
    @Getter
    private final int code;
    @Getter
    private final String description;
    @Getter
    private final HttpStatus httpStatus;

    BusinessErrorCodes(int code, HttpStatus httpStatus, String description) {
        this.code = code;
        this.description = description;
        this.httpStatus = httpStatus;
    }
}
