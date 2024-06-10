# TIME SLEEP FOR THREAD RESTART
sleep_thread_restart = 10
sleep_thread_socket_restart = 60

# PARAMETER FOR API SERVICE BINDING
management_host = "127.0.0.1"
management_port = 5000

# LINUX AND MACOS DIRECTORY EXCLUSIONS FROM SCAN
linux_dir_exclusions = ["/proc/", "/dev/", "/sys/", "/usr/src/linux/", "/opt/yara", "/var/lib/apt/lists/"]

# GENERAL EXTENSION EXCLUSIONS FROM SCAN
extension_exclusions = [".yar", ".yara", ".h", ".pem", ".crt", ".dat", ".dat-old", ".cache", ".crash", ".db", ".log", ".swp", ".swpx"]

# DIRECTORY SET FOR FS HOOKS
# DYNAMIC GENERATION: A FIND COMMAND IS RUN USING voyeur_linux_top_dirs ELEMENT AS PATH AND voyeur_dirs_wild AS EXPRESSION AND RESULT IS USED
# STATIC GENERATION: voyeur_dirs_nowild IS USED DIRECTLY AS DIRECTORY
voyeur_linux_top_dirs = ['/']
voyeur_mac_top_dirs = []
voyeur_dirs_wild = ["download", "downloads", "Download", "Downloads", "Scaricati"]
voyeur_dirs_nowild = ["/tmp"]

# MAX SIZE FILE TO CHECK BY SCAN
max_file_size = 52428800

# YARA RULES WHITELIST
yara_whitelist = ["SurtrStrings", "Surtr"]

# HASH WHITELIST
hash_whitelist = ["1ebbd3e34237af26da5dc08a4e440464"]

# IP WHITELIST
ip_whitelist = ["1.1.1.1"]
