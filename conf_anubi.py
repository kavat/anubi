# TIME SLEEP FOR THREAD RESTART
sleep_thread_restart = 10
sleep_thread_socket_restart = 60

# PARAMETER FOR API SERVICE BINDING
management_host = "127.0.0.1"
management_port = 5000

# LINUX AND MACOS DIRECTORY EXCLUSIONS FROM SCAN
linux_dir_exclusions = ["/proc/", "/dev/", "/sys/", "/usr/src/linux/", "/opt/yara", "/var/lib/apt/lists/"]

# GENERAL EXTENSION EXCLUSIONS FROM SCAN
extension_exclusions = [".yar", ".yara", ".h", ".pem", ".crt", ".dat", ".dat-old", ".cache", ".crash", ".db", ".log"]

# DYNAMIC STRINGS DIRECTORY FOR FS HOOKS, USING *_top_dir VARIABLE A FIND COMMAND WILL BE EXECUTED TO OBTAIN FULL PATH INTERPOLATING TOP DIR OCCURRENCE WITH WILD DIRECTORIES
voyeur_dirs_wild = ["download", "downloads", "Download", "Downloads", "Scaricati"]
voyeur_linux_top_dirs = ['/']
voyeur_mac_top_dirs = []
# STATIC STRINGS DIRECTORY FOR FS HOOKS
voyeur_dirs_nowild = ["/tmp"]

# MAX SIZE FILE TO CHECK BY SCAN
max_file_size = 52428800
