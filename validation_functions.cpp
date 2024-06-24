// validation_functions.cpp

#include "validation_functions.hpp"


std::vector<std::string> split(const std::string& str, char delimiter) 
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) 
    {
        tokens.push_back(token);
    }
    return tokens;
}

// Validate Username
bool isValidUsername(const std::string& username) {
    if (username.size() > 20)
        return false;
    for (char c : username) {
        if (!std::isalnum(c) && c != '-')
            return false;
    }
    return true;
}

// Validate ChannelID
bool isValidChannelID(const std::string& channelID) {
    if (channelID.size() > 20)
        return false;
    for (char c : channelID) {
        if (!std::isalnum(c) && c != '-')
            return false;
    }
    return true;
}

// Validate Secret
bool isValidSecret(const std::string& secret) {
    return secret.size() <= 128 && std::all_of(secret.begin(), secret.end(), [](char c) {
        return std::isalnum(c) || c == '-';
    });
}

// Validate DisplayName
bool isValidDisplayName(const std::string& displayName) {
    return displayName.size() <= 20 && std::all_of(displayName.begin(), displayName.end(), [](char c) {
        return std::isprint(c) && c >= 0x21 && c <= 0x7E;
    });
}

// Validate MessageContent
bool isValidMessageContent(const std::string& messageContent) {
    return messageContent.size() <= 1400 && std::all_of(messageContent.begin(), messageContent.end(), [](char c) {
        return std::isprint(c) && c >= 0x20 && c <= 0x7E;
    });
}

// Funkce pro převod řetězce na velká písmena
std::string toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

// Recieve message content from recieved data
std::string concatenateMessageContent(const std::vector<std::string>& parts, size_t startIndex) {
    std::string messageContent;
    for (size_t i = startIndex; i < parts.size(); ++i) {
        messageContent += parts[i];
        if (i < parts.size() - 1) {
            messageContent += ' '; // Adding a space between words
        }
    }
    return messageContent;
}

// Check if the incomming tcp message is in valid format.
bool is_valid_message(const std::string& message) 
{
    if (message.empty()) 
    {
        return false;
    }
    std::string messageContent;
    std::string upper_data = toUpper(message);
    std::vector<std::string> parts = split(upper_data, ' ');

    if(parts[0] == "ERR" && parts.size() >= 5)
    {
        if (parts[1] == "FROM" && isValidDisplayName(parts[2]) && parts[3] == "IS") 
        {
            for (size_t i = 4; i < parts.size(); ++i) {
                messageContent += parts[i];
                if (i < parts.size() - 1) {
                    messageContent += ' '; // Add space
                }
            }
            
            if(!isValidMessageContent(messageContent))
            {
                return false;
            };
            return true;
        }
        else 
        {
            return false;
        }
    }
    else if(parts[0] == "REPLY" && parts.size() >= 4)
    {
        if((parts[1] == "OK" || parts[1] == "NOK") && parts[2] == "IS")
        {
            for (size_t i = 3; i < parts.size(); ++i) {
                messageContent += parts[i];
                if (i < parts.size() - 1) {
                    messageContent += ' '; // Add space
                }
            }
            
            if(!isValidMessageContent(messageContent))
            {
                return false;
            };
            return true;
        }
        else
        {
            return false;
        }
    }
    else if(parts[0] == "AUTH" && parts.size() == 6)
    {
        if(isValidUsername(parts[1]) && parts[2] == "AS" && isValidDisplayName(parts[3]) && parts[4] == "USING" && isValidSecret(parts[5]))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else if(parts[0] == "JOIN" && parts.size() == 4)
    {
        if(parts[2] == "AS" && isValidDisplayName(parts[3]))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else if(parts[0] == "MSG" && parts.size() >= 5)
    {
        if(parts[1] == "FROM" && isValidDisplayName(parts[2]) && parts[3] == "IS")
        {
            for (size_t i = 4; i < parts.size(); ++i) {
                messageContent += parts[i];
                if (i < parts.size() - 1) {
                    messageContent += ' '; // Add space
                }
            }

            if(!isValidMessageContent(messageContent))
            {
                return false;
            };
            return true;
        }
        else
        {
            return false;
        }
    }
    else if(parts[0] == "BYE" && parts.size() == 1)
    {
        return true;
    }
    else
    {
        return false;
    }
    return false;   
}
