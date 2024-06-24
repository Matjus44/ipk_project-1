#ifndef MESSAGEBUILDER_H
#define MESSAGEBUILDER_H

#include <string>

class MessageBuilder {
public:
    MessageBuilder() {}  // Construct

    // Methods for creating of message for tcp.
    static std::string buildERR(const std::string& displayName, const std::string& messageContent);
    static std::string buildREPLY(bool isOk, const std::string& messageContent);
    static std::string buildAUTH(const std::string& arg1, const std::string& arg2, const std::string& arg3);
    static std::string buildJOIN(const std::string& channelID, const std::string& displayName);
    static std::string buildMSG(const std::string& displayName, const std::string& messageContent);
    static std::string buildBYE(const std::string& arg1);
};

#endif /* MESSAGEBUILDER_H */