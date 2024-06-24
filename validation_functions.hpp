#ifndef VALIDATION_FUNCTIONS_HPP
#define VALIDATION_FUNCTIONS_HPP

#include <string>
#include <string>
#include <cctype>
#include <algorithm>
#include <regex>
#include <vector>
#include <iostream>

// Declaration
bool isValidUsername(const std::string& username);
bool isValidChannelID(const std::string& channelID);
bool isValidSecret(const std::string& secret);
bool isValidDisplayName(const std::string& displayName);
bool isValidMessageContent(const std::string& messageContent);
bool is_valid_message(const std::string& messages);
std::vector<std::string> split(const std::string& str, char delimiter);
std::string toUpper(const std::string& str);
std::string concatenateMessageContent(const std::vector<std::string>& parts, size_t startIndex);

#endif // VALIDATION_FUNCTIONS_HPP