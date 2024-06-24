#ifndef STRUCTURES_H
#define STRUCTURES_H

// Define the states of the FSM
enum State {
    START_STATE,
    AUTH_STATE,
    OPEN_STATE,
    ERROR_STATE,
    END_STATE
};

// Define the inputs to the FSM with specific values
enum Input {
    CONFIRM = 0x00,
    REPLY = 0x01,
    AUTH = 0x02, // Updated to match the pattern
    JOIN = 0x03, // Updated to match the pattern
    MSG = 0x04,
    ERR = 0xFE,
    BYE = 0xFF,
    NOT_TYPE = 0x55
};

// Define error messages with specific values
enum ErrorMessage {
    INVALID_COMMAND = 50,
    CONNECTION_FAILED = 51,
    AUTHENTICATION_FAILED = 52,
    JOIN_FAILED = 53,
    MESSAGE_SEND_FAILED = 54,
    MESSAGE_CONTENT = 55,
    TIMEOUT_OCCURRED = 56,
    MAX_RETRY_EXCEEDED = 57,
    SERVER_ERROR = 58,
    UNDEFINED_ERROR = 59,
    SELECTOR_ERROR = 60,
    NOT_RECIEVED_MESSAGE = 61,
    INTERNAL_ERROR = 62,
    GRAMMAR_ERROR = 63
};

#endif // STRUCTURES_H