# IPK Projekt 1: Klient pre chat server pomocou IPK24-CHAT protokolu

## Obsah
- [Úvod](#úvod)
- [Teoretický základ](#teoretický-základ)
- [Architektúra aplikácie](#architektúra-aplikácie)
  - [Obsah repozitáru](#obsah-repozitáru)
  - [Start programu](#start-programu)
  - [TCP varianta](#tcp-varianta)
  - [UDP varianta](#udp-varianta)
  - [UML a Sekce kódu](#UML-a-Sekca-Kódu)
- [Testovanie](#testovanie)
  - [Dôvod testovania](#Dôvod-testovania)
  - [Spôsob testovania](#Spôsob-testovania)
  - [Testovacie prípady a vstup/výstup](#Testovacie-prípady-a-vstup/výstup)
    - [UDP](#udp)
    - [TCP](#tcp)
- [Extra funkcionality](#extra-funkcionality)
- [Bibliografia](#bibliografia)

## Úvod
Tento dokument poskytuje prehľad a dokumentáciu k implementácii klienta pre komunikáciu s vzdialeným serverom používajúcim protokol IPK24-CHAT. Protokol má dve varianty založené na transportných protokoloch TCP a UDP. Dokumentácia sa zameriava na popis funkcionality implementovanej aplikácie, testovania a porovnania s podobnými nástrojmi.

## Teoretický základ
IPK24-CHAT je komunikačný protokol navrhnutý pre výmenu správ medzi klientom a serverom. Podporuje autentifikáciu, pripojenie k chatovacím kanálom a výmenu správ medzi účastníkmi. Protokol má variantu TCP A UDP. Obydva protokoly sú implementované podľa automatu špecifikovaného v zadaní.
TCP varianta protokolu IPK24-CHAT poskytuje spoľahlivú komunikáciu medzi klientom a serverom prostredníctvom transportného protokolu TCP (Transmission Control Protocol). Táto varianta je navrhnutá tak, aby zabezpečila, že všetky správy odoslané medzi klientom a serverom dorazia v poradí, v ktorom boli odoslané, a bez straty alebo poškodenia. Výhodou TCP varianty je jej spoľahlivosť a jednoduchosť implementácie.
UDP (User Datagram Protocol) je jednoduchý, bezspoľahlivý sieťový protokol v rámci transportnej vrstvy modelu OSI (Open Systems Interconnection). Oproti TCP (Transmission Control Protocol), UDP nezabezpečuje spoľahlivú komunikáciu, nezaručuje doručenie dát v správnom poradí alebo bez chýb, čo môže viesť k strate paketov alebo duplicite paketov.

## Architektúra aplikácie

### Obsah repozitáru
Program bol rozčlenený do niekoľkoých častí. `Main.c` obsahuje hlavnú logiku a implementáciu jednotlivých stavov. `Message.cpp` obsahuje triedu Message ktorá má atributy parametre správ a metódy pre vytváranie jednotlivých správ. `validation_functions.cpp` obsahuje implementáciu jednotlivých funkcií pre validáciu parametrov a formátu prichádzajúcej správy. Deklarácia týchto funkcií sa nachádza v `validation_functions.hpp`. `structures.h` obsahuje enum štruktúry a enum ukončujúcich správ. `MessageBuilder.cpp` obsahuje implemnatáciu metód pre vytváranie tcp správ. `MessageBuilder.hpp` obsahuje deklaráciu a triedy jednotlivých metód.
Súčasťou programu je tiež `Makefile`.

### Start programu
Program začína vo funkcii v súbore `main.c` vo funkcii `main` , kde ako prvé sa skontrolujú prijaté argumenty cez terminál a následne sa uložia do premenných. Program vytvorí `socket` podľa aktuálneho protokolu. Získa a správne nastavý adresu serveru a port. Nastavím `file descriptors` na prípadné čítanie a príjmanie a prechádaza do smyčky v ktorej sa nachádza stavový automat. Podľa protokolu sa následne komunikuje so serverom.

### TCP varianta

Pre vytváranie jednotlivých správ sme použili triedu `MessageBuilder` ktorá obsahuje metódy na správne vytvorenie správy. Pre kontrolu správnosti údajov vkládané do správy bolo implementovaných niekoľko funkcií ako napríklad `isValidName` `isValidDisplayName` a niekoľko dalších.Protokol podporuje `/help` ktorý vypíše nápovedu. Program je možné ukončiť pomocou `ctrl+c`.


- **START_STATE:** Klient začína komunikáciu s serverom iniciáciou TCP spojenia. Po úspešnom napojení sa prechádza do funkcie `processStartState` v ktorom úživateľ posiela spravu prostredníctvom `send`. Pri úspešnom vytvorení odoslaní správy sa presúvame do stavu `AUTH_STATE` v opačnom prípade načítávame vstup znovu.

- **AUTH_STATE:** V tomto stave pomocou funkcie `selector` môžme príjmať správy od serveru a zároveň aj správu poslať. Najskôr mi príde odpoveď na autorizačnú správu ktorá bola poslaná v `START_STATE`. Gramatika prijatej správy bude skontrolovaná pomocou funkcie `is_valid_message` a následne sa spracuje podľa jej typu. Ak jej typ bude `REPLY` a odpoveď pozitívna tak sa presunieme do stavu `OPEN_STATE`. Ak správa bude mať typ `ERROR` tak prejdeme do stavu `ERROR_STATE`, v prípade `BYE` ukončujeme program. Vprípade nevalidnej gramatiky opäť načítame vstup.

- **OPEN_STATE:** Pomocou funkcie `selector` program príjma a zároveň odosiela správy. Skontroluje sa gramatika a odošle sa správa odpovedajúca typu vstupu. Ak je typ odosielanej správy `JOIN` tak vstup je blokovaný dokiaľ nezískame odpoveď od serveru. Každá prichádzajúca správa je opäť skontrolovaná pomocou funkcie `is_valid_message` a následne spracovaná. Možnosť použiť `/rename` na premenovanie zobrazovacieho mena.

- **END_STATE:** Konečný stav v ktorom sa ukončí spojenie medzi užívateľom a serverom pomocou `close(sockfd)`, a program sa ukončí `exit(0)`. Ešte pred ukončením program pošle serveru správu typu BYE.

- **ERROR_STATE:** V prípade že server pošle neočakávanú správu tak program prejde do tohoto stavu kde klient pošle serveru správu prečo nastala chyba. Na ukladanie chybovej hlášky slúží premenná `error_from_user_content` ktorej obsah bude poslaný ako obsah správy na server. Po odoslaní správý program prejde do `END_STATE`.
  
### UDP varianta
Pre vytváranie jednotlivých správ sme využili triedu `Message` ktorej si vytvoríme inštanciu a následne cez jej metódu vytvoríme paketu. Pre kontrolovanie gramatiky správ sme opäť využili funkcie implementované v súbore `validation_functions.cpp`. Pre vypisovanie jednotlivých paket od serveru boli implementované funkcie `printReplyMessageContent` , `printMessageContent` a `printErrorMessage` . Narozdiel od tcp, nevytvárame 1:1 spojenie so serverom. V prípade že po odoslaní správy na server neobdržíme správu typu `confirm` so zhodným ID tak paketu posielame znovu, pre túto funkcionalitu bola implementovaná funkcia `waitForConfirmation`. Protokol podporuje `/help` ktorý vypíše nápovedu. Program je možné ukončiť pomocou `ctrl+c`.

- **START_STATE:** Komunikácia so serverom je platná až v po úspešnej autorizácii. Paketu posielame pomocou funkcie `waitForConfirmation`. Ak daná funkcia vráti hodnotu false tak indikuje že sa nám nepodarilo získať potvrdenie a program prejde do `ERROR_STATE`

- **AUTH_STATE:** V tomto stave pomocou funkcie `selector` môžme príjmať pakety od serveru a zároveň aj paketu poslať. Najskôr mi príde odpoveď na autorizačnú paketu ktorá bola poslaná v `START_STATE`. Gramatika skontrolovaná. Ak odpoveď nebola pozitívna tak posielame znovu autorizačnú paketu. V tomto stave sa správa posiela mimo funkcie `waitForConfirmation` z dôvodu paralelného príjmania a odosielania správ. V prípade že som neobdržal `confirm` tak je vstup blokovaný dovtedy dokial ho program neobdrží. Každej prijatej správe je skontrolovaný typ. Pre spôsob opakovaného odosielania pakety pri používaní selector je výztrižok kódu v sekcii sekce kódu.

- **OPEN_STATE:** Pomocou funkcie `selector` program príjma a zároveň odosiela pakety. Skontroluje sa gramatika a odošle sa správa odpovedajúca typu vstupu. Opäť správa nie je posielaná funkciou `waitForConfirmation`. Vtomto stave sa program môže pripojiť do rôznych kanálov a odosielať paketu typu MSG taktiež je tu možnosť `/rename` ktorý premenuje zobrazovacie meno.

- **END_STATE:** Konečný stav v ktorom sa ukončí spojenie medzi užívateľom a serverom pomocou `close(sockfd)`, a program sa ukončí `exit(0)`. Ešte pred ukončením program pošle serveru paketu typu BYE opäť pomocou waitForConfirmation.

- **ERROR_STATE:** V prípade že server pošle neočakávanú paketu tak program prejde do tohoto stavu kde klient pošle serveru paketu prečo nastala chyba. Na ukladanie chybovej hlášky slúží premenná `error_from_user_content` ktorej obsah bude poslaný ako obsah pakety na server. Pre odoslanie pakety bola použitá funkcia waitForConfirmattion ale aj v prípade že confirm nebol doručený tak prejdeme do `END_STATE`.


### Zaujímavé sekcie zdrojového kódu
V tejto sekcií sú ukázané jednotlivé implementaácie problémov.

Ukázka implementace opakovaného zasielania správy
```
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
```
Ukázka implementace nastavenia selectoru

```
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
```

Ukázka funkcie waitForConfirm ktorá posiela opakovane správu

```
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
```

## Testovanie

### Dôvod testovania:
- Vylepšenie a overenie funkcionality programu.

### Testovacie prostredie:
- Wireshark za pomocou skriptu ipk24.chat.

### Testovacie prípady a vstup/výstup:

#### UDP

1. Neobdržanie confirm správy. V prípade že program sa nachádzal v open stave tak som mu zmenil čakanie na confirm na 1, tým pádom mi neprišlo potvrdenie do daného časového intervalu a zároveň som mu správu opakovane poslal.
```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
ahoj
```
   **Výstup bol očakávaný v tomto poradí:** \
   Správna autorizácia, pozitívna odpoveď. \
   Opakované zasielanie správy.

![not_recieved_confirm_UDP](/images/not_recieved_confirm_UDP.png "not_recieved_confirm_UDP")

2. Blokovanie vstupu pri čakaní na reply a confirm. Pri spustení súboru pomocou presmerovania vstupu program rýchlo čítal po riadku zo stdin a tým pádom tam bolo kritické blokovanie vstupu. 
```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
/join discord.verified-1
ahoj toto je sprava
ahoj toto je dalsia sprava
```
**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Poslanie JOIN a počkanie na odpoveď. \
Následne odoslanie správ v správnom poradí.  

![wait_reply_UDP](/images/wait_reply_UDP.png "wait_reply_UDP")

3. Pripojenie do kanálu. Zaslatie packety ktorá ponesie správny typ správy join. 
```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
/join discord.verified-1
```
**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Poslanie JOIN a počkanie na odpoveď.

![join_UDP](/images/join_UDP.png "join_UDP")

4. Testovanie eof (čítanie zo súboru). 
```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
/join discord.verified-1
```
**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Poslanie JOIN a počkanie na odpoveď. \
Poslanie BYE na server a ukončenie programu.

![eof_UDP](/images/eof_UDP.png "eof_UDP")

5. Testovanie ctrlc. Manuálne zadávanie príkazov do command line. 
```
/auth toto je spatne
SIGINT
```
**Výstup bol očakávaný v tomto poradí:** \
Nesprávna autorizácia, negativna odpoveď. \
Poslanie BYE na server a ukončenie programu.

![ctrlc_UDP](/images/ctrlc_UDP.png "ctrlc_UDP")

6. Autorizácia. Poslanie autorizačnej packety cez command line. 
```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
SIGINT
```
**Výstup bol očakávaný v tomto poradí:** \
Nesprávna autorizácia, negativna odpoveď. \
Poslanie BYE na server a ukončenie programu.

![valid_auto_UDP](/images/valid_auto_UDP.png "valid_auto_UDP")

7. Neplatá autorizácia. Poslanie neplatnej autorizačnej packety cez command line 
```
/auth toto je spatne
SIGINT
```
**Výstup bol očakávaný v tomto poradí:** \
Nesprávna autorizácia, negativna odpoveď. \
Poslanie BYE na server a ukončenie programu.

![not_valid_autoris_UDP](/images/not_valid_autoris_UDP.png "not_valid_autoris_UDP")

#### TCP

1. Pripojenie sa do kanálu. Poslať správu typu join a dostať odpoveď.
```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
/join discord.verified-1
```
**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Poslanie JOIN a počkanie na odpoveď. \
Poslanie BYE na server a ukončenie programu.

![join_tcp](/images/join_tcp.png "join_tcp")

2. Blokovanie vstupu pri čakaní na reply. Pri spustení súboru pomocou presmerovania vstupu program rýchlo čítal po riadku zo stdin a tým pádom tam bolo kritické blokovanie vstupu.

```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
/join discord.verified-1
ahoj toto je sprava
ahoj toto je dalsia sprava
```
**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Poslanie JOIN a počkanie na odpoveď. \
Následne odoslanie správ v správnom poradí.  

![reply_wait_tcp](/images/reply_wait.png "reply_wait_tcp")

3. Testovanie premenovania. Zadať command line argument /rename.

```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
ahoj toto je sprava
/rename anopane
ahoj toto je dalsia sprava
```

**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Poslanie správy. \
Poslanie správy s novým menom. \

![rename_tcp](/images/rename%20tcp.png "rename_tcp")

4. Testovanie pokusu o poslanie nesprávneho typy v open_state.

```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
ahoj toto je sprava
/rename anopane
ahoj toto je dalsia sprava
/join discord.verified-1
/auth toto nemozem poslat
ahoj som tu znovu
```
**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Poslanie správy. \
Poslanie správy s novým menom. \
Poslanie JOIN a pozitívna odpoveď. \
Odoslanie správy ahoj som tu znovu (preskočenie pokusus o zaslanie auth v open_state)

![wrong_msg_type_tcp](/images/wrong_msg_type.png "wrong_msg_type_tcp")

5. Pokus o odoslanie spravy v auth_state.
```
/auth toto je spatne
ahoj toto je sprava
```
**Výstup bol očakávaný v tomto poradí:** \
Nesprávna autorizácia, negativna odpoveď. \
Ukončenie programu (preskočenie odoslania správy). 

![wrong_msg_type_in_auth_state_tcp](/images/wrong_msg_type_in_auth_state_tcp.png "wrong_msg_type_in_auth_state_tcp")

6. Autorizácia. Poslanie autorizačnej správy cez command line.
```
/auth xjanek05 9690d975-db7f-4e9c-a120-f47a8699324d anop
SIGINT
```
**Výstup bol očakávaný v tomto poradí:** \
Správna autorizácia, pozitívna odpoveď. \
Ukončenie programu a zaslanie BYE.

![valid_auth_tcp](/images/valid_auth_tcp.png "valid_auth_tcp")

7. Neplatá autorizácia. Poslanie neplatnej autorizačnej správy cez command line. 

```
/auth toto je spatne
SIGINT
```

**Výstup bol očakávaný v tomto poradí:** \
Nesprávna autorizácia, negativna odpoveď. \
Ukončenie programu (preskočenie odoslania správy). 

![wron_auth_tcp](/images/wron_auth_tcp.png "wron_auth_tcp")


## Extra funkcionality
Vrámci extra funkcionality nebolo nič implementované.

## Bibliografia

[1]: Daniel Dolejška. (2024, February 29). *IPK Kamerový záznam* [online]. Publisher: Brno University of Technology. Retrieved March 5, 2024, [cit. 2024-03-10] Available at: [https://www.youtube.com/watch?v=OKuZ_JO9sLw&list=PL_eb8wrKJwYv0INj2tRYT15csQXcKxTg1&index=3](https://www.youtube.com/watch?v=OKuZ_JO9sLw&list=PL_eb8wrKJwYv0INj2tRYT15csQXcKxTg1&index=3)


[2]: Daniel Dolejška. (2024, February 29). *IPK2023-24L-04-PROGRAMOVANI.pdf* [online]. Publisher: Brno University of Technology. Retrieved March 10, 2024, [cit. 2024-03-10] Available at: [https://moodle.vut.cz/mod/folder/view.php?id=402680](https://moodle.vut.cz/mod/folder/view.php?id=402680)

[3]: NESFIT . (2024). *Documentation Instructions* , IPK Projects 2024 [online]. Publisher: Brno University of Technology. Retrieved March 31, 2024, [cit. 2024-03-10] Available at: [https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024#documentation-instructions](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024#documentation-instructions)

[4]: NESFIT . (2024). *Project 1* , IPK Projects 2024 [online]. Publisher: Brno University of Technology. Retrieved March 31, 2024, [cit. 2024-03-10] Available at: [https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%201](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%201)