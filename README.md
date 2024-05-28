# Anubi
IOC/Hash scanner and IDS layer 4 designed to be portable and fast

Anubi is a tool desgined and written in Python in order to be flexible and usable on different platform.

## Functions
Anubi combines four different engines to check your assets:
1. IOC scanner
2. Hash scanner
3. IP check
4. Filesystem modifications

These functionalities use a prepared set of rules available in [my repository](https://github.com/kavat/anubi-signatures) generated daily.

### IOC scanner
Scan is a passive monitoring on the filesystem root applying Yara rules generated in [my official repo](https://github.com/kavat/anubi-signatures/tree/main/yara)

### Hash scanner
Scan is a passive monitoring on the filesystem root applying Hash rules generated in [my official repo](https://github.com/kavat/anubi-signatures/tree/main/hash)

### IP checker
Scan is a passive monitoring on the filesystem root applying IP rules generated in [my official repo](https://github.com/kavat/anubi-signatures/tree/main/ip)

### Filesystem modifications
Scan is an active monitoring on the filesystem directories specified (as default system tries to identify Downlaods and media such USB) applying previously [Yara](https://github.com/kavat/anubi-signatures/tree/main/yara) and [Hash](https://github.com/kavat/anubi-signatures/tree/main/hash) rules

## Run
Anubi is developed to be run on Linux and further release will provides same functions on Windows and Mac.

In order to print full options, run Anubi with --help; the following options will be returned:

![Anubu help](images/anubi_help.png)

In details, options available are the following:
1.  -h, --help       Used to show the current help message and exit
2.  --check-conf     Used to check the current configuration and exit
3.  --check-struct   Used to check Anubi directory structure and exit
4.  --create-struct  Used to create Anubi directory structure needed and exit
5.  --init           Used to init runtime.dat configuration file in order to set features to protect us and exit
6.  --start          Used to start Anubi with configuration created (if runtime.dat is not present, it will be created before starting)
7.  --wipe           Used to erase Anubi logs and exit
