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
*  -h, --help       used to show the current help message and exit
*  --check-conf     used to check the current configuration and exit
*  --check-struct   used to check Anubi directory structure and exit
*  --create-struct  used to create Anubi directory structure needed and exit
*  --init           used to init runtime.dat configuration file in order to set features to protect us and exit
*  --start          used to start Anubi with configuration created and rules already present
*  --start-full     used to start Anubi with configuration created (if runtime.dat is not present, it will be created before starting), rules will be downloaded or updated
*  --wipe           used to erase Anubi logs and exit

## OS supported
Linux, MacOS and Windows are supported by Anubi engine.

## Dependencies
External dependencies are needed:
* Git
  * Linux (Debian): `apt install git-core`
  * Linux (Centos): `yum install git-core`
  * MacOS: `brew install git`
  * Windows: `Install-Module posh-git -Scope CurrentUser -Force`
* Python3
  * Linux (Debian): `apt install python3`
  * Linux (Centos): `yum install python3`
  * MacOS: `brew install python3`
  * Windows: follow [official documentation](https://www.python.org/downloads/windows/)
* Python3 Pip
  * Linux (Debian): `apt install python3-pip` or `python3 -m ensurepip`
  * Linux (Centos): `yum install python3-pip` or `python3 -m ensurepip`
  * MacOS: `python3 -m ensurepip`
  * Windows: Pip will be install with Python3 installation, follow [official documentation](https://www.python.org/downloads/windows/)
* YARA
  * Linux/Windows: follow [official documentation](https://yara.readthedocs.io/en/stable/gettingstarted.html) 
  * MacOS: `brew install yara`

Relating di Pip modules, install dependecies through `pip install -r pip_requirements.txt`
