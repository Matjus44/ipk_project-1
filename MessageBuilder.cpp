#include "MessageBuilder.hpp"
#include <sstream>

std::string MessageBuilder::buildERR(const std::string& displayName, const std::string& messageContent) {
    
    std::string message = "ERR FROM " + displayName + " IS " + messageContent + "\r\n";
    return message;
}

std::string MessageBuilder::buildREPLY(bool isOk, const std::string& messageContent) {
    std::ostringstream oss;
    oss << "REPLY\tREPLY " << (isOk ? "\"OK\"" : "\"NOK\"") << " IS " << messageContent << "\r\n";
    return oss.str();
}

std::string MessageBuilder::buildAUTH(const std::string& arg1, const std::string& arg2, const std::string& arg3) {
    std::string message = "AUTH " + arg1 + " AS " + arg2 + " USING " + arg3 + "\r\n";
    return message;
}

std::string MessageBuilder::buildJOIN(const std::string& channelID, const std::string& displayName) {
    std::string message = "JOIN " + channelID + " AS " + displayName + "\r\n";
    return message;
}

std::string MessageBuilder::buildMSG(const std::string& displayName, const std::string& messageContent) {
    std::string message = "MSG FROM " + displayName + " IS " + messageContent + "\r\n";
    return message;
}

std::string MessageBuilder::buildBYE(const std::string& arg1) {
    std::string message = arg1 + "\r\n";
    return message;
}
