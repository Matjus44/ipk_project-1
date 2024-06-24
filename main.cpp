#include "structures.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <array>
#include <sstream>
#include <iomanip>
#include <vector>
#include "message.cpp"
#include <sys/epoll.h>
#include <sys/select.h>
#include <fcntl.h>
#include "validation_functions.hpp"
#include <atomic>
#include <csignal>
#include "MessageBuilder.hpp"

std::atomic<bool> terminateSignalReceived(false);

// Function for checking is sigint was recieved.
void signalHandler(int signal) {
    if(signal){
        if (signal == SIGINT) {
            terminateSignalReceived.store(true);
        }
    } 
}

void segfaultHandler(int signum) {
    if(signum){
        std::cerr << "ERR: Fatal error occurred." << std::endl;
        exit(1);
    }
}


// Global variabile for ID
uint16_t messageID = 0x0000;
std::string error_from_user_content;

// Helper function to convert command string to Input enum
Input commandStringToInput(const std::string& commandStr)
{
    if (commandStr == "/CONFIRM") return CONFIRM;
    if (commandStr == "/REPLY") return REPLY;
    if (commandStr == "/auth") return AUTH;
    if (commandStr == "/join") return JOIN;
    if (commandStr == "/MSG") return MSG;
    if (commandStr == "/ERR") return ERR;
    if (commandStr == "/BYE") return BYE;
    return NOT_TYPE;
}

std::string convertToHex(Input input) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(input);
    return oss.str();
}

// Print reply in correct format.
void printReplyMessageContent(const char* buffer)
{
    char result = buffer[3];
    // Extracting message content
    std::string messageContent;
    for (int i = 6; buffer[i] != '\0'; i++) {
        messageContent += buffer[i];
    }

    if (result == 0x00) {
        std::cerr << "Failure: " << messageContent << std::endl;
    } else if (result == 0x01) {
        std::cerr << "Success: " << messageContent << std::endl;
    }
}

// Print incomming message in correct format.
void printMessageContent(const char* buffer)
{
    std::string name;
    for (int i = 3; buffer[i] != '\0'; i++) {
        name += buffer[i];
    }

    // Extracting message content
    std::string messageContent;
    for (int i = 3 + name.length() + 1; buffer[i] != '\0'; i++) {
        messageContent += buffer[i];
    }

    std::cout << name << ": " << messageContent << std::endl;
}

// Print error message in correct format.
void printErrorMessage(const char* buffer) {
    std::string name;
    for (int i = 3; buffer[i] != '\0'; i++) {
        name += buffer[i];
    }

    // Extracting message content
    std::string messageContent;
    for (int i = 3 + name.length() + 1; buffer[i] != '\0'; i++) {
        messageContent += buffer[i];
    }

    std::cerr << "ERR FROM " << name << ": " << messageContent << std::endl;
}

bool waitForConfirmation(int sockfd, const char* message, size_t message_size, sockaddr* address, socklen_t address_size, int flags, uint16_t timeout, uint8_t retry, uint16_t expectedMessageID) {
    int attempts = 0;
    bool confirmed = false;
    struct timeval tv;
    fd_set readfds;

    // Set socket to non blocking
    int current_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, current_flags | O_NONBLOCK);

    while (attempts < (retry + 1) && !confirmed) {
        // Send msg.
        if (sendto(sockfd, message, message_size, flags, address, address_size) < 0)
        {
            error_from_user_content = "Failed to send some content";
            std::cerr << "ERR: " << error_from_user_content << std::endl;
            exit(MESSAGE_SEND_FAILED);
        }

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        // Timeout
        tv.tv_sec = timeout / 1000;  
        tv.tv_usec = (timeout % 1000) * 1000;  

        // Wait for confirm
        while (select(sockfd + 1, &readfds, NULL, NULL, &tv) > 0) {
            if (FD_ISSET(sockfd, &readfds)) {
                char buffer[1024];
                if (recvfrom(sockfd, buffer, sizeof(buffer), flags, address, &address_size) >= 0) {
                    uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                    if (receivedMessageID == expectedMessageID && buffer[0] == 0x00) {
                        confirmed = true;
                        break; // Recieved confirm with correct id, breal.
                    }
                } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    // Process possible error.
                    error_from_user_content = "blocked";
                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                    break;
                }
            }
            // Reset timeout a readfds for next iteeration.
            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;
        }

        if (!confirmed) {
            attempts++;
        } else {
            break; // Recieved confirm.
        }
    }

    // Set back to blocking
    fcntl(sockfd, F_SETFL, current_flags);

    return confirmed;
}

// Print help for user.
void printhelp()
{
        std::cout << R"(/auth	{Username} {DisplayName} {Secret}:
Sends AUTH message with the data provided from the command to the server.
/join	{ChannelID} :
Sends JOIN message with channel name from the command to the server.
/rename	{DisplayName}:
Locally changes the display name of the user to be sent with new messages/selected commands.
)";
}

// In this stae we create auth message, we check his grammar if grammar is incorrect then we have to insert auth again untill the grammar is correct, then we go to AUTH_STATE
// where we process reply.
State processStartState(int sockfd, sockaddr* address, socklen_t address_size, int flags, uint16_t timeout, uint8_t retry, std::string& display_name)
{
    bool sending = true;

    while(sending == true)
    {
        std::string line;
        std::getline(std::cin, line); // Read

        if(terminateSignalReceived.load())
        {   // Sigint
            close(sockfd); 
            exit(0); 
        }

        if (std::cin.eof())
        {
            // Endofline
            close(sockfd);
            exit(0);
        }
        // Empty line
        if(line.empty())
        {
            error_from_user_content = "Grammar of auth command incorrect";
            std::cerr << "ERR: " << error_from_user_content << std::endl;
        }
        else
        {
            std::vector<std::string> parts = split(line, ' ');

            if (parts.size() == 4)
            {
                Input messageType_1 = commandStringToInput(parts[0]);
                std::string hexValue = convertToHex(messageType_1);

                display_name = parts[3];
                Message authMessage(hexValue, parts[1], display_name, parts[2], messageID,"","");
                std::string final_message = authMessage.constructAuthMessage();

                if((isValidUsername(parts[1]) != false && isValidDisplayName(display_name) != false && isValidSecret(parts[3]) != false) && parts[0] == "/auth")
                {
                    if (!waitForConfirmation(sockfd, final_message.c_str(), final_message.size(), address, address_size, flags, timeout, retry,messageID))
                    {
                        error_from_user_content = "Timeout expired";
                        std::cerr << "ERR: " << error_from_user_content << std::endl;
                        close(sockfd);
                        exit(1);
                    }
                    return AUTH_STATE;
                }
                else
                {

                    error_from_user_content = "Grammar of auth command incorrect";
                    std::cerr << "ERR: " << error_from_user_content << std::endl;

                }
            }
            else
            {
                if(parts[0] == "/help" && parts.size() == 1)
                {
                    printhelp();
                }
                else
                {
                    error_from_user_content = "Grammar of auth command incorrect";
                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                }
            }
        }
    }
    return AUTH_STATE;
}

State processAuthState(int sockfd,fd_set& readfds, sockaddr* address, socklen_t address_size, int flags ,std::string& display_name,uint16_t timeout, uint8_t retry)
{
    bool connected = false;
    char buffer[1500];
    int reply;
    bool reply_wait = true;
    bool wait_for_confirm = false;
    int numRetries = 0;
    messageID += 0x0001;
    std::string final_message;
    while(connected == false)
    {
        // Set fds and selector
        fd_set tmp_fds = readfds;

        int num_ready_fds = select(sockfd + 1, &tmp_fds, NULL, NULL, NULL);
        if (num_ready_fds < 0)
        {
            if (errno == EINTR && terminateSignalReceived.load())
            {
                return END_STATE;
            }
            else
            {
                error_from_user_content = "Internal selector error u are here";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                return ERROR_STATE;
            }
        }

        int numReadyFds;

        timeval tv;
        if (wait_for_confirm)
        {
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;
            numReadyFds = select(sockfd + 1, &tmp_fds, NULL, NULL, &tv);
        }
        else
        {
            numReadyFds = select(sockfd + 1, &tmp_fds, NULL, NULL, NULL);
        }

        // Did we hit timeout ? -> resend the message.
        if (wait_for_confirm && numReadyFds == 0)
        {
            if (numRetries < retry)
            {   // Still can resend.
                int resend = sendto(sockfd, final_message.c_str(), final_message.size(), flags, address, address_size);
                if (resend < 0)
                {
                    error_from_user_content = "Failed to resend message";
                    return ERROR_STATE;
                }
                wait_for_confirm = true;
                numRetries++;
            }
            else
            {   // Did not resend the message -> ERROR_STATE.
                error_from_user_content = "Timeout expired";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                close(sockfd);
                exit(1);
            }
        }

        if(FD_ISSET(STDIN_FILENO, &tmp_fds) && reply_wait == false && wait_for_confirm == false)
        {
            std::string line;
            std::getline(std::cin, line);

            if (std::cin.eof())
            {
                return END_STATE;
            }

            if(reply_wait == false && line.empty() == false)
            {
                std::vector<std::string> parts = split(line, ' ');

                if(parts.size() == 4)
                {
                    Input messageType_1 = commandStringToInput(parts[0]);                               // BUFFER[0] CHECK ADD.
                    std::string hexValue = convertToHex(messageType_1);

                    display_name = parts[3];

                    if((isValidUsername(parts[1]) == false || isValidDisplayName(display_name) == false || isValidSecret(parts[3]) == false) || parts[0] != "/auth")
                    {
                        error_from_user_content = "Auth grammar error";
                        std::cerr << "ERR: " << error_from_user_content << std::endl;
                    }
                    else
                    {
                        Message authMessage(hexValue, parts[1], display_name, parts[2], messageID,"","");

                        final_message = authMessage.constructAuthMessage();

                        int auth_send = sendto(sockfd, final_message.c_str(), final_message.size(), flags, address, address_size);
                        if(auth_send < 0)
                        {
                            error_from_user_content = "Auth failed to send";
                            return ERROR_STATE;
                        }
                        reply_wait = true;
                        wait_for_confirm = true;
                    }
                }
            }
            else
            {
                if(line == "/help")
                {
                    printhelp();
                }
                else
                {
                    error_from_user_content = "Auth grammar error";
                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                }
            }
        }

        if (FD_ISSET(sockfd, &tmp_fds))
        {
            reply = recvfrom(sockfd, buffer, sizeof(buffer), flags, address, &address_size);

            if (reply < 0)
            {
                error_from_user_content = "No reply recieved";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                return ERROR_STATE;
            }
            // Reply
            if(buffer[0] == 0x01)
            {
                std::uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage("0x00", "", "", "", receivedMessageID,"","");
                std::string confirmMsg = confirmMessage.constructConfirmMessage();
                printReplyMessageContent(buffer);
                int confirmSend = sendto(sockfd, confirmMsg.c_str(), confirmMsg.size(), flags, address, address_size);
                if(confirmSend < 0)
                {
                    error_from_user_content = "Failed to send confirm";
                    connected = false;
                    return ERROR_STATE;
                }
                if(buffer[3] == 0x01)
                {
                    connected = false;
                    return OPEN_STATE;
                }
                reply_wait = false;
            }
            // Error
            else if((buffer[0] & 0xfe) == ERR)
            {
                std::uint16_t ID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage3("0x00", "", "", "", ID,"","");
                std::string confirmMsg3 = confirmMessage3.constructConfirmMessage();
                printErrorMessage(buffer);
                int confirm_to_bye_from_server = sendto(sockfd, confirmMsg3.c_str(), confirmMsg3.size(), flags, address, address_size);
                if(confirm_to_bye_from_server < 0)
                {
                    error_from_user_content = "Failed to send confirm";
                    return ERROR_STATE;
                }
                connected = false;
                return END_STATE;
            }
            else if(buffer[0] == 0x00)
            {
                std::uint16_t ID = (buffer[1] << 8) | buffer[2];
                if(messageID == ID)
                {
                    messageID += 0x0001;
                    wait_for_confirm = false;
                    numRetries = 0;
                }

            }
            else
            {
                error_from_user_content = "Incorrect server message in open state";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                std::uint16_t ID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage3("0x00", "", "", "", ID,"","");
                std::string confirmMsg3 = confirmMessage3.constructConfirmMessage();
                int confirm_to_bye_from_server = sendto(sockfd, confirmMsg3.c_str(), confirmMsg3.size(), flags, address, address_size);
                if(confirm_to_bye_from_server < 0)
                {
                    close(sockfd);
                    exit(1);
                }
                return ERROR_STATE;
            }
        }
    }
    return END_STATE;
}

// Process open state, recieve or send data to server, first check datas grammar, and then process it.
State process_open_state(int sockfd, fd_set& readfds, std::string& display_name, sockaddr* address, socklen_t address_size, uint16_t timeout, uint8_t retry)
{
    int flags = 0;
    int numRetries = 0;
    char buffer[1500];
    bool stopRecieving = false;
    bool reply_recieved = true;
    bool wait_for_confirm = false;
    std::string send_to_server;
    while (!stopRecieving) {
        // Set fds.
        fd_set tmp_fds = readfds;
        int numReadyFds;
        // Set selector according to the fact if we send something to the server.
        timeval tv;
        if (wait_for_confirm)
        {
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;
            numReadyFds = select(sockfd + 1, &tmp_fds, NULL, NULL, &tv);
        }
        else
        {
            numReadyFds = select(sockfd + 1, &tmp_fds, NULL, NULL, NULL);
        }

        if (numReadyFds < 0)
        {
            if (errno == EINTR && terminateSignalReceived.load())
            {
                return END_STATE;
            }
            std::cerr << "ERR: Internal selector error" << std::endl;
            return ERROR_STATE;
        }

        // If we did not recieve confirm we need to resend the message.
        if (wait_for_confirm && numReadyFds == 0)
        {
            if (numRetries < retry)
            {   // We can still resend
                int resend = sendto(sockfd, send_to_server.c_str(), send_to_server.size(), flags, address, address_size);
                if (resend < 0)
                {
                    error_from_user_content = "Failed to resend message";
                    return ERROR_STATE;
                }
                wait_for_confirm = true;
                numRetries++;
            }
            else
            {   // Message resended 3 times -> ERROR_STATE
                error_from_user_content = "Timeout expired";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                close(sockfd);
                exit(1);
            }
        }
        // STDIN is ready.
        if (FD_ISSET(STDIN_FILENO, &tmp_fds) && wait_for_confirm == false && reply_recieved == true)
        {
            // Read from stdin
            std::string line;
            if (std::cin.eof())
            {
                return END_STATE;
            }

            std::getline(std::cin, line);

            if (line.empty() == false)
            {
                if(reply_recieved == true)
                {
                    std::vector<std::string> parts = split(line, ' ');
                    std::string hexValue = "";

                    Input messageType_1 = commandStringToInput(parts[0]);

                    if (messageType_1 != NOT_TYPE) {
                        hexValue = convertToHex(messageType_1);
                    }

                    if(reply_recieved == true)
                    {
                        if((parts[0].starts_with("/") && parts[0] == "/join") || !parts[0].starts_with("/") || parts[0] == "/rename")
                        {
                            // Send join message.
                            if(hexValue == "0x03")
                            {
                                if(parts.size() == 2 && isValidDisplayName(display_name))
                                {
                                    Message joinmessage(hexValue,"",display_name,"", messageID,parts[1],"");
                                    send_to_server = joinmessage.constructJoinMessage();
                                    int send_join = sendto(sockfd, send_to_server.c_str(), send_to_server.size(), flags, address, address_size);
                                    if(send_join < 0)
                                    {
                                        error_from_user_content = "Failed to send join message";
                                        return ERROR_STATE;
                                    }
                                    wait_for_confirm = true;
                                    reply_recieved = false;
                                }
                                else
                                {
                                    error_from_user_content = "Join grammar error";
                                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                                }

                            }
                            else if(parts[0] == "/rename")
                            {
                                if(parts.size() == 2)
                                {
                                    if(isValidDisplayName(parts[1]) == true)
                                    {
                                        display_name = parts[1];
                                    }
                                    else
                                    {
                                        error_from_user_content = "Display name incorrect";
                                        std::cerr << "ERR: " << error_from_user_content << std::endl;
                                    }
                                }
                                else
                                {
                                    error_from_user_content = "Too many arguments with /rename argument";
                                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                                }
                            }
                            // Send msg message.
                            else
                            {
                                if(isValidMessageContent(line) != false && isValidDisplayName(display_name) != false )
                                {
                                    Message msg("0x04", "", display_name, "", messageID, "", line);
                                    send_to_server = msg.constructMsgMessage();
                                    int send_msg = sendto(sockfd, send_to_server.c_str(), send_to_server.size(), flags, address, address_size);
                                    if(send_msg < 0)
                                    {
                                        error_from_user_content = "Timeout expired, did not recieve confirm";
                                        return ERROR_STATE;
                                    }
                                    wait_for_confirm = true;
                                }
                                else
                                {
                                    error_from_user_content = "Message grammar error";
                                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                                }
                            }
                        }
                        else
                        {
                            if(parts[0] == "/help" && parts.size() == 1)
                            {
                                printhelp();
                            }
                            else
                            {
                                error_from_user_content = "Grammar error in open state";
                                std::cerr << "ERR: " << error_from_user_content << std::endl;
                            }
                        }
                    }
                }
            }
            else
            {
                error_from_user_content = "Empty line";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
            }
        }

        // Socket is ready to recieve
        if (FD_ISSET(sockfd, &tmp_fds)) {
            // Recieve msg
            int serverReply = recvfrom(sockfd, buffer, sizeof(buffer), flags, address, &address_size);
            if (serverReply < 0)
            {
                error_from_user_content = "Failed to recieve message";
                return ERROR_STATE;
            }
            // Message
            if (buffer[0] == 0x04)
            {
                std::uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage("0x00", "", "", "", receivedMessageID,"","");
                std::string confirmMsg = confirmMessage.constructConfirmMessage();
                int confirmSend = sendto(sockfd, confirmMsg.c_str(), confirmMsg.size(), flags, address, address_size);
                if(confirmSend < 0)
                {
                    error_from_user_content = "Failed to send confirm";
                    return ERROR_STATE;
                }
                printMessageContent(buffer);
                stopRecieving = false;
            }
            // Reply
            else if(buffer[0] == 0x01)
            {
                std::uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage("0x00", "", "", "", receivedMessageID,"","");
                std::string confirmMsg = confirmMessage.constructConfirmMessage();
                int confirmSend = sendto(sockfd, confirmMsg.c_str(), confirmMsg.size(), flags, address, address_size);
                if(confirmSend < 0)
                {
                    error_from_user_content = "Failed to send confirm";
                    return ERROR_STATE;
                }
                printReplyMessageContent(buffer);
                reply_recieved = true;
                stopRecieving = false;
            }
            // Error
            else if((buffer[0] & 0xfe) == ERR)
            {
                std::uint16_t ID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage3("0x00", "", "", "", ID,"","");
                std::string confirmMsg3 = confirmMessage3.constructConfirmMessage();
                printErrorMessage(buffer);
                int confirm_to_bye_from_server = sendto(sockfd, confirmMsg3.c_str(), confirmMsg3.size(), flags, address, address_size);
                if(confirm_to_bye_from_server < 0)
                {
                    error_from_user_content = "Failed to send confirm";
                    return ERROR_STATE;
                }
                return END_STATE;
            }
            // Bye
            else if(static_cast<uint16_t>(buffer[0]) == 0xff)
            {
                std::uint16_t ID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage3("0x00", "", "", "", ID,"","");
                std::string confirmMsg3 = confirmMessage3.constructConfirmMessage();
                int confirm_to_bye_from_server = sendto(sockfd, confirmMsg3.c_str(), confirmMsg3.size(), flags, address, address_size);
                if(confirm_to_bye_from_server < 0)
                {
                    error_from_user_content = "Failed to send confirm";
                    return ERROR_STATE;
                }
                stopRecieving = true;
                close(sockfd);
                exit(0);
            }
            else if(buffer[0] == 0x00)
            {
                std::uint16_t ID = (buffer[1] << 8) | buffer[2];
                if(messageID == ID)
                {
                    messageID += 0x0001;
                    numRetries = 0;
                    wait_for_confirm = false;
                }
            }
            else
            {
                error_from_user_content = "Incorrect server message in open state";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                std::uint16_t ID = (buffer[1] << 8) | buffer[2];
                Message confirmMessage3("0x00", "", "", "", ID,"","");
                std::string confirmMsg3 = confirmMessage3.constructConfirmMessage();
                int confirm_to_bye_from_server = sendto(sockfd, confirmMsg3.c_str(), confirmMsg3.size(), flags, address, address_size);
                if(confirm_to_bye_from_server < 0)
                {
                    close(sockfd);
                    exit(1);
                }
                return ERROR_STATE;
            }
        }
    }
    return END_STATE;
}

// Process end state for udp, construct message and send it to server, also wait for confirm and then close file descriptors and exit programmar with 0.
State process_end_state(int sockfd, sockaddr* address, socklen_t address_size, uint16_t timeout, uint8_t retry)
{
    int flags = 0;
    Message bye_msg("0xff", "", "", "", messageID, "", "");
    std::string byemsg = bye_msg.constructByeMessage();
    if(!waitForConfirmation(sockfd, byemsg.c_str(), byemsg.size(), address, address_size, flags, timeout, retry,messageID))
    {
        error_from_user_content = "Timeout expired";
        std::cerr << "ERR: " << error_from_user_content << std::endl;
        close(sockfd);
        exit(1);
    }
    close(sockfd);
    exit(0);
}

// Process error state for udp, construct message and send it to server, also wait for confirm and then go to END_STATE.
State process_error_state(int sockfd, std::string& display_name, sockaddr* address, socklen_t address_size, uint16_t timeout, uint8_t retry)
{
    int flags = 0; // Flags if needed.
    Message error_msg("0xff", "", display_name, "", messageID, "", error_from_user_content);
    std::string errormsg = error_msg.constructErrorMessage();
    if (!waitForConfirmation(sockfd, errormsg.c_str(), errormsg.size(), address, address_size, flags, timeout, retry,messageID))
    {
        error_from_user_content = "Timeout expired";
        std::cerr << "ERR: " << error_from_user_content << std::endl;
        close(sockfd);
        exit(1);
    }
    messageID += 0x0001;
    return END_STATE;
}

// Process Start state tcp.
State processStartStateTCP(int sockfd, std::string& display_name,fd_set& readfds)
{
    bool sending = true;
    // Loop till we dont construct auth command with valid grammar.
    while(sending == true)
    {
        // Set fds and selector.
        fd_set tmp_fds = readfds;
        int numReadyFds;

        numReadyFds = select(sockfd + 1, &tmp_fds, NULL, NULL, NULL);

        if (numReadyFds < 0)
        {
            if (errno == EINTR && terminateSignalReceived.load())
            {
                return END_STATE;
            }
            error_from_user_content = "Selector error";
            std::cerr << "ERR: " << error_from_user_content << std::endl;
            close(sockfd);
            exit(1);
        }

        // Create auth command, check his grammar and send it to server.
        if (FD_ISSET(STDIN_FILENO, &tmp_fds))
        {
            std::string line;
            std::getline(std::cin, line);

            if (std::cin.eof())
            {
                sending = false;
                return END_STATE;
            }
            if(line.empty())
            {
                error_from_user_content = "Grammar of auth command incorrect";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
            }
            else
            {
                std::vector<std::string> parts = split(line, ' ');

                if (parts.size() == 4)
                {
                    display_name = parts[3];
                    std::string upper_type = toUpper(parts[0]);
                    if((isValidUsername(parts[1]) != false && isValidDisplayName(display_name) != false && isValidSecret(parts[3]) != false) && upper_type == "/AUTH")
                    {
                        // Grammar was correct send it to server and go to AUTH_STATE.
                        std::string authMessage = MessageBuilder::buildAUTH(parts[1], display_name, parts[2]);
                        send(sockfd, authMessage.c_str(), authMessage.size(), 0);
                        sending = false;
                        return AUTH_STATE;
                    }
                    else
                    {
                        error_from_user_content = "Grammar of auth command incorrect";
                        std::cerr << "ERR: " << error_from_user_content << std::endl;
                    }
                }
                else
                {
                    if(parts[0] == "/help" && parts.size() == 1)
                    {
                        printhelp();
                    }
                    else
                    {
                        error_from_user_content = "Grammar of auth command incorrect";
                        std::cerr << "ERR: " << error_from_user_content << std::endl;
                    }
                }
            }
        }
        // FD is ready to recieve, so process the recieved data check grammar and process the type.
        if (FD_ISSET(sockfd, &tmp_fds))
        {
            std::array<char, 1500> buffer{0};
            int bytes_rx = read(sockfd, buffer.data(), 1500);
            if(bytes_rx < 0)
            {
                error_from_user_content = "Did not recieve message";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                close(sockfd);
                exit(1);
            }
            std::string something = buffer.data();
            std::size_t pos = something.find("\r\n");
            if (pos != std::string::npos) {
                // If found, erase it
                something.erase(pos);
            }
            if(!is_valid_message(something))
            {
                error_from_user_content = "Recieved malformed data";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                return ERROR_STATE;
            }
            std::vector<std::string> parts = split(something, ' ');
            std::string upper_type = parts[0];
            if(upper_type == "ERR" || upper_type == "err")
            {
                sending = false;
                std::string msg_con = concatenateMessageContent(parts,4);
                std::cerr << "ERR FROM " << parts[2] << ": " << msg_con << std::endl;
                return END_STATE;
            }
            else if( upper_type == "BYE")
            {
                return END_STATE;
            }
            else
            {
                error_from_user_content = "Recieved wrong type of message";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                sending = false;
                return ERROR_STATE;
            }
        }
    }
    return AUTH_STATE;
}

// Process auth state in tcp.
State processAuthStateTCP(int sockfd, std::string& display_name,fd_set& readfds)
{
    bool loop = true;
    bool recieved_reply = false;
    while(loop)
    {
        // Set fd.
        fd_set tmp_fds = readfds;
        int numReadyFds;

        // Selector
        numReadyFds = select(sockfd + 1, &tmp_fds, NULL, NULL, NULL);

        if (numReadyFds < 0)
        {
            if (errno == EINTR && terminateSignalReceived.load())
            {
                return END_STATE;
            }
            std::cerr << "ERR: Selector error" << std::endl;
            close(sockfd);
            exit(1);
        }

        // Fd is ready to read, in this case we can only send join message, we check his grammar and send it to server, otherwise its an error.
        if (FD_ISSET(STDIN_FILENO, &tmp_fds) && recieved_reply == true)
        {
            std::string line;
            std::getline(std::cin, line);

            if (std::cin.eof())
            {
                loop = false;
                return END_STATE;
            }

            if(recieved_reply == true && line.empty() == false)
            {
                std::vector<std::string> parts = split(line, ' ');

                if(parts.size() == 4)
                {
                    std::string upper_type = toUpper(parts[0]);
                    if((isValidUsername(parts[1]) == false || isValidDisplayName(display_name) == false || isValidSecret(parts[3]) == false) || upper_type != "/AUTH")
                    {
                        error_from_user_content = "Auth grammar error";
                        std::cerr << "ERR: " << error_from_user_content << std::endl;
                    }
                    else
                    {
                        display_name = parts[3];
                        std::string authMessage = MessageBuilder::buildAUTH(parts[1], display_name, parts[2]);
                        send(sockfd, authMessage.c_str(), authMessage.size(), 0);
                        recieved_reply = false;
                    }
                }
                else
                {
                    error_from_user_content = "Auth grammar error";
                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                }
            }
            else
            {
                if(line == "/help")
                {
                    printhelp();
                }
                else
                {
                    error_from_user_content = "Auth grammar error";
                    std::cerr << "ERR: " << error_from_user_content << std::endl;
                }
            }
        }
        
        // Fd is ready to recieve, again we process incomming message, if incomming messages grammar is incorrect then return error.
        if (FD_ISSET(sockfd, &tmp_fds))
        {
            std::array<char, 1500> buffer{0};
            int bytes_rx = read(sockfd, buffer.data(), 1500);
            if(bytes_rx < 0)
            {
                std::cerr << "ERR: Did not send message" << std::endl;
                close(sockfd);
                exit(1);
            }

            std::string something = buffer.data();
            std::size_t pos = something.find("\r\n");
            if (pos != std::string::npos) {
                // If found, erase it
                something.erase(pos);
            }
            if(!is_valid_message(something))
            {
                error_from_user_content = "Recieved malformed data";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                return ERROR_STATE;
            }
            std::vector<std::string> parts = split(something, ' ');
            std::string upper_type = parts[0];
            if(upper_type == "REPLY" || upper_type == "reply")
            {
                std::string upper_answer = parts[1];
                std::string msg_con = concatenateMessageContent(parts,3);
                if(upper_answer == "OK")
                {
                    loop = false;
                    std::cerr << "Success: " << msg_con << std::endl;
                    return OPEN_STATE;
                }
                else if(upper_answer == "NOK")
                {
                    std::cerr << "Failure: " << msg_con << std::endl;
                    recieved_reply = true;
                }

            }
            else if(upper_type == "ERR" || upper_type == "err")
            {
                loop = false;
                std::string msg_con = concatenateMessageContent(parts,4);
                std::cerr << "ERR FROM " << parts[2] << ": " << msg_con << std::endl;
                return END_STATE;
            }
            else
            {
                loop = false;
                error_from_user_content = "Recieved wrong type of message";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                return ERROR_STATE;
            }
        }
    }
    return END_STATE;
}

// Process open state in tcp.
State process_open_stateTCP(int sockfd, std::string& display_name,fd_set& readfds)
{
    // Loop.
    bool stop_recieving = false;
    // Message that will be send to server.
    std::string send_to_server;
    // Waiting for reply if necessary.
    bool recieved_reply = true;

    while(stop_recieving == false)
    {
        // Create temporary file descriptos and selector..
        fd_set tmp_fds = readfds;
        int numReadyFds;

        numReadyFds = select(sockfd + 1, &tmp_fds, NULL, NULL, NULL);

        if (numReadyFds < 0)
        {
            // recieved ctrl+c -> END_STATE.
            if (errno == EINTR && terminateSignalReceived.load())
            {
                return END_STATE;
            }
            std::cerr << "ERR: Internal selector error" << std::endl;
            close(sockfd);
            exit(1);
        }

        // File descriptor is ready to read.
        if (FD_ISSET(STDIN_FILENO, &tmp_fds) && recieved_reply == true)
        {
            // Read from stdin.
            std::string line;
            if (std::cin.eof())
            {
                return END_STATE;
            }

            std::getline(std::cin, line);

            if (line.empty() == false)
            {
                std::vector<std::string> parts = split(line, ' ');
                // Checking for valid command or message.
                std::string upper_type = toUpper(parts[0]);
                if((parts[0].starts_with("/") && parts[0] == "/JOIN") || !parts[0].starts_with("/") || upper_type == "/RENAME" || upper_type == "/JOIN" || upper_type == "/RENAME")
                {
                    // Send join message.
                    if(upper_type == "/JOIN")
                    {
                        if(parts.size() == 2)
                        {
                            std::string join_msg = MessageBuilder::buildJOIN(parts[1], display_name);
                            int send_join = send(sockfd, join_msg.c_str(), join_msg.size(), 0);
                            if(send_join < 0)
                            {
                                std::cerr << "ERR: Did not send message" << std::endl;
                                close(sockfd);
                                exit(1);
                            }
                            recieved_reply = false;
                        }
                        else
                        {
                            error_from_user_content = "Join grammar error";
                            std::cerr << "ERR: " << error_from_user_content << std::endl;
                        }

                    }
                    // Command rename used to rename display name.
                    else if(upper_type == "/RENAME")
                    {
                        if(parts.size() == 2)
                        {
                            if(isValidDisplayName(parts[1]) == true)
                            {
                                display_name = parts[1];
                            }
                            else
                            {
                                error_from_user_content = "Display name incorrect";
                                std::cerr << "ERR: " << error_from_user_content << std::endl;
                            }
                        }
                        else
                        {
                            error_from_user_content = "Too many arguments with /rename argument";
                            std::cerr << "ERR: " << error_from_user_content << std::endl;
                        }
                    }
                    // Send msg message.
                    else
                    {
                        if(isValidMessageContent(line) != false && isValidDisplayName(display_name) != false )
                        {
                            std::string send_msg = MessageBuilder::buildMSG(display_name,line);
                            int send_msg_con = send(sockfd, send_msg.c_str(), send_msg.size(), 0);
                            if(send_msg_con < 0)
                            {
                                std::cerr << "ERR: Did not send message" << std::endl;
                                close(sockfd);
                                exit(1);
                            }
                        }
                        else
                        {
                            error_from_user_content = "Message grammar error";
                            std::cerr << "ERR: " << error_from_user_content << std::endl;
                        }
                    }
                }
                // Invalid grammar of message, but still might be /help otherwise error.
                else
                {
                    if(parts[0] == "/help" && parts.size() == 1)
                    {
                        printhelp();
                    }
                    else
                    {
                        error_from_user_content = "Grammar error in open state";
                        std::cerr << "ERR: " << error_from_user_content << std::endl;
                        // return ERROR_STATE;
                    }
                }
            }
            // Empty line
            else
            {
                error_from_user_content = "Empty line";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
            }
        }
        // Sokcet is ready to recieve.
        if (FD_ISSET(sockfd, &tmp_fds))
        {
            std::array<char, 1500> buffer{0};
            int bytes_rx = read(sockfd, buffer.data(), 1500);
            if(bytes_rx < 0)
            {
                std::cerr << "ERR: Did not send message" << std::endl;
                close(sockfd);
                exit(1);
            }
            // Remove \r\n from message.
            std::string something = buffer.data();
            std::size_t pos = something.find("\r\n");
            if (pos != std::string::npos) {
                // If found, erase it.
                something.erase(pos);
            }
            // Are recieved data valid ?
            if(!is_valid_message(something))
            {
                error_from_user_content = "Recieved malformed data";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                return ERROR_STATE;
            }
            std::vector<std::string> parts = split(something, ' ');
            std::string upper_type = toUpper(parts[0]);

            // Process message, if message doesnt match any of expected, then go to ERROR_STATE.
            if(upper_type == "REPLY" || upper_type == "reply")
            {
                std::string upper_answer = parts[1];
                std::string msg_con = concatenateMessageContent(parts,3);
                if(upper_answer == "OK")
                {
                    std::cerr << "Success: " << msg_con << std::endl;
                    recieved_reply = true;
                }
                else if(upper_answer == "NOK")
                {
                    std::cerr << "Failure: " << msg_con << std::endl;
                    recieved_reply = true;
                }
            }
            else if(upper_type == "BYE" || upper_type == "bye")
            {
                close(sockfd);
                exit(0);
            }
            else if(upper_type == "ERR" || upper_type == "err")
            {
                stop_recieving = true;
                std::string msg_con = concatenateMessageContent(parts,4);
                std::cerr << "ERR FROM " << parts[2] << ": " << msg_con << std::endl;
                return END_STATE;
            }
            else if(upper_type == "MSG" || upper_type == "msg")
            {
                std::string msg_con = concatenateMessageContent(parts,4);
                std::cout << parts[2] << ": " << msg_con << std::endl;
            }
            else
            {
                error_from_user_content = "Recieved wrong type of message";
                std::cerr << "ERR: " << error_from_user_content << std::endl;
                stop_recieving = true;
                return ERROR_STATE;
            }
        }
    }
    return ERROR_STATE;
}

// Process end state in tcp, create byt message, close socket and exit(0).
State process_end_state_tcp(int sockfd)
{
    std::string bye_mesasge = MessageBuilder::buildBYE("BYE");
    int send_msg_con = send(sockfd, bye_mesasge.c_str(), bye_mesasge.size(), 0);
    if(send_msg_con < 0)
    {
        close(sockfd);
        exit(1);
    }
    close(sockfd);
    exit(0);
}

// Process error state  in tcp, create error message and send it to server, then proceeding into END_STATE.
State process_error_state_tcp(int sockfd, std::string& display_name)
{
    std::string error_msg = MessageBuilder::buildERR(display_name,error_from_user_content);
    int send_msg_con = send(sockfd, error_msg.c_str(), error_msg.size(), 0);
    if(send_msg_con < 0)
    {
        close(sockfd);
        exit(1);
    }
    return END_STATE;
}

int main(int argc, char *argv[]) {
    int option;
    std::string protocol, server_hostname;
    int port = 4567; // Default port
    uint16_t timeout = 250; // Default timeout for UDP
    uint8_t retry = 3; // Default retry for UDP
    std::signal(SIGINT, signalHandler);
    std::signal(SIGSEGV, segfaultHandler);

    while ((option = getopt(argc, argv, "t:s:p:d:r:h")) != -1) {
        switch (option) {
            case 't':
                protocol = optarg;
                break;
            case 's':
                server_hostname = optarg;
                break;
            case 'p':
                port = std::stoi(optarg);
                break;
            case 'd':
                timeout = std::stoi(optarg);
                break;
            case 'r':
                retry = std::stoi(optarg);
                break;
            case 'h':
            case '?': // Uknown argument
            default:
                std::cout << "Usage: " << argv[0] << " -t <tcp|udp> -s <server> [-p <port>] [-d <timeout>] [-r <retry>] [-h]" << std::endl;
                return EXIT_FAILURE;
        }
    }

    int sockfd;

    // Create socket tcp/udp
    if(protocol == "udp")
    {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            std::cerr << "Socket not created " << std::strerror(errno) << std::endl;
            exit(INTERNAL_ERROR);
        }
    }
    if(protocol == "tcp")
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            std::cerr << "Socket not created " << std::strerror(errno) << std::endl;
            exit(INTERNAL_ERROR);
        }
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, server_hostname.c_str(), &addr) == 1)
    {
        // IP adress
    }
    else
    {
        // Hostname get ip adress
        struct hostent *server = gethostbyname(server_hostname.c_str());
        if (server == NULL) {
            std::cerr << "ERROR: Nemožno získať IP adresu pre " << server_hostname << std::endl;
            exit(INTERNAL_ERROR);
        }
        memcpy(&addr, server->h_addr_list[0], sizeof(struct in_addr));
    }

    // Set adress of server
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr = addr; 
    server_address.sin_port = htons(port);

    struct sockaddr *address = (struct sockaddr *) &server_address;
    socklen_t address_size = sizeof(server_address);

    // Starting state
    State current_state = START_STATE;

    int flags = 0;

    fd_set readfds;

    FD_ZERO(&readfds); // Setting file descriptors.

    // Add stdin
    FD_SET(STDIN_FILENO, &readfds);

    // Add sockfd
    FD_SET(sockfd, &readfds);


    std::string display_name;

    while (1)
    {
        switch (current_state)
        {
            case START_STATE:
            {
                if(protocol == "udp")
                {
                    current_state = processStartState(sockfd, address, address_size, flags, timeout, retry, display_name);
                }
                else
                {
                    if (connect(sockfd, address, address_size) < 0)
                    {
                        std::cerr << "ERR: connection " << std::strerror(errno) << std::endl;
                        close(sockfd); // Close the socket if connection fails
                        exit(EXIT_FAILURE);
                    }
                    current_state = processStartStateTCP(sockfd, display_name,readfds);
                }
                break;
            }

            case AUTH_STATE:
            {
                if(protocol == "udp")
                {
                    current_state = processAuthState(sockfd,readfds, address, address_size, flags, display_name,timeout,retry);
                }
                else
                {
                    current_state = processAuthStateTCP(sockfd,display_name,readfds);
                }
                break;
            }

            case OPEN_STATE:
            {
                if(protocol == "udp")
                {
                    current_state = process_open_state(sockfd, readfds, display_name, address, address_size, timeout, retry);
                }
                else
                {
                    current_state = process_open_stateTCP(sockfd,display_name,readfds);
                }
                break;
            }
            case END_STATE:
            {
                if(protocol == "udp")
                {
                    current_state = process_end_state(sockfd, address, address_size, timeout, retry);
                    return 0;
                    
                }
                else
                {
                    current_state = process_end_state_tcp(sockfd);
                    return 0;
                }
                break;
            }

            case ERROR_STATE:
            {
                if(protocol == "udp")
                {
                    current_state = process_error_state(sockfd, display_name, address, address_size, timeout, retry);
                }
                else
                {
                    current_state = process_error_state_tcp(sockfd,display_name);
                }
                break;
            }

            default:
                std::cout << "Wrong state" << std::endl;
                return 1;
        }
    }
    return 0;
}
