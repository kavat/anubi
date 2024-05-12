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
