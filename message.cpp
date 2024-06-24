#ifndef MESSAGE_CPP
#define MESSAGE_CPP

#include <string>

class Message {
public:
    std::string type_name = ""; 
    std::string username = "";
    std::string display_name = "";
    std::string secret = "";
    std::uint16_t ID; 
    std::string channel = ""; 
    std::string message_contents = ""; 

    // Construct
     Message(const std::string& type, const std::string& user, const std::string& display, const std::string& sec, const std::uint16_t id, const std::string& ch, const std::string& contents)
    : type_name(type), username(user), display_name(display), secret(sec), ID(id), channel(ch), message_contents(contents) {}

    // Create auth msg.
    std::string constructAuthMessage() const 
    {
        std::string message;
        message += '\x02'; 
        message += static_cast<uint8_t>((ID >> 8) & 0xFF); 
        message += static_cast<uint8_t>(ID & 0xFF); 
        message += username + '\x00' + display_name + '\x00' + secret + '\x00';
        return message;
    }

    // Create confirm msg.
    std::string constructConfirmMessage() const 
    {
        std::string message;
        message += '\x00'; 
        message += static_cast<uint8_t>((ID >> 8) & 0xFF); 
        message += static_cast<uint8_t>(ID & 0xFF); 
        return message;
    }

    // Create join msg.
    std::string constructJoinMessage() const 
    {
        std::string message;
        message += '\x03'; 
        message += static_cast<uint8_t>((ID >> 8) & 0xFF); 
        message += static_cast<uint8_t>(ID & 0xFF); 
        message += channel + '\x00' + display_name + '\x00';
        return message;
    }

    // Create bye msg.
    std::string constructByeMessage() const 
    {
        std::string message;
        message += '\xFF'; // Typ zprávy BYE
        message += static_cast<uint8_t>((ID >> 8) & 0xFF); 
        message += static_cast<uint8_t>(ID & 0xFF); 
        return message;
    }

    // Create msg.
    std::string constructMsgMessage() const 
    {
        std::string message;
        message += '\x04'; 
        message += static_cast<uint8_t>((ID >> 8) & 0xFF); 
        message += static_cast<uint8_t>(ID & 0xFF); 
        message += display_name + '\x00' + message_contents + '\x00';
        return message;
    }

    // Create error msg.
    std::string constructErrorMessage() const 
    {
        std::string message;
        message += '\xFE';
        message += static_cast<uint8_t>((ID >> 8) & 0xFF); 
        message += static_cast<uint8_t>(ID & 0xFF); 
        message += display_name + '\x00' + message_contents + '\x00';
        return message;
    }
};

#endif // MESSAGE_H