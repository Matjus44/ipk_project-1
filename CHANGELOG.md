# Changelog

Všetký výrazné zmeny sú zaznamenané v tomto dokumente.

Odkazy sú presmerované na daný "commit".

V odstavci probémy je opísaný potenciálny problém.

## Zmeny

[Mar 31, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/880545a8b691b3307dc1b68c1c04e6cf8b8de779)
Pridanie CHANGELOG.md 

[Mar 30, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/da741f3577efec0d349bf4da48f26a229728318a)
Úprava dokumentácie 

[Mar 30, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/081d56a6a32238cf4294066d1da9930bcf225eb6)
Pridanie vypisovanie na výstup v niektorých prípadoch.

[Mar 29, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/cfc95260839ce4cfef8f6f2ab58240fa9ffee6c6)
Zavedenie paralelného príjmania a odosielania správy v auth_state u tcp protokolu.

[Mar 29, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/307e6ab1db7f11fb39ca5b1a0f06ef17479e9b61)
Zmena ukončenia programu pri neprijatí confirm u udp.

[Mar 28, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/cf43c33df92ddecb25854bd479242758f132078c)
Zmena poradia príjmania argumentov u príkazu auth tcp a udp


[Mar 28, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/5c973a8c1965b41ba1a3683ca2c958cf334ad3d9)
Fungujúci TCP protokol, úprava pôvodného

[Mar 27, 2024](https://git.fit.vutbr.cz/xjanek05/ipk/commit/93093a58c05ca4feb429027ff0922b65df4c58db)
FungujúcI UDP protokol, pridanie triedy Message, Makefile, Validačních funkcíí

## Problémy

### Popis problému

Protokol udp aj tcp funguje na spôsobu čakania správy typu `REPLY` ktorú server musí vždy poslať po zaslaní na server paketu alebo správu typu `JOIN` alebo `AUTH`.
Problém ale nastal v tom že u udp protokolu sa časový interval čakania na paketu vzťahuje iba na typ `CONFIRM`, tým pádom problém môže nastať v tom prípade že program bude
čakať na paketu `REPLY` ktorej sa nikdy nedočká a zároveň je vstup blokovaný vzhľadom nato že čakáme a tak nieje možné ukončiť program pomocou `ctrlc` alebo načítaním `eof`.
U tcp je problém rovanký iba stým rozdielom že sa knemu nevzťahuje žiadny interval čakania na správu typu `CONFIRM`.

### Potenciálne riešenie

Riešením by mohlo byť zavedenie časového intervalu aj v prípade čakania na `REPLY` u tcp aj udp. V prípade že danú správu alebo paketu neobdržíme tak ukončíme komunikáciu so serverom pomocou uzavretiu socket a ukončenie programu pomocou chybovej hlášky. Tým zabezpečíme problém nekonečného čakania.

