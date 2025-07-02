# TIME SLEEP FOR THREAD RESTART
sleep_thread_restart = 10
sleep_thread_socket_restart = 60

# PARAMETER FOR API SERVICE BINDING
management_host = "127.0.0.1"
management_port = 5555

# LINUX AND MACOS DIRECTORY EXCLUSIONS FROM SCAN
linux_dir_exclusions = ["/proc/", "/dev/", "/sys/", "/usr/src/linux/", "/opt/yara", "/var/lib/apt/lists/"]

# GENERAL EXTENSION EXCLUSIONS FROM SCAN
extension_exclusions = [".yar", ".yara", ".h", ".pem", ".crt", ".dat", ".dat-old", ".cache", ".crash", ".db", ".log", ".swp", ".swpx"]

# DIRECTORY SET FOR FS HOOKS
# DYNAMIC GENERATION: A FIND COMMAND IS RUN USING voyeur_linux_top_dirs ELEMENT AS PATH AND voyeur_dirs_wild AS EXPRESSION AND RESULT IS USED
# STATIC GENERATION: voyeur_dirs_nowild IS USED DIRECTLY AS DIRECTORY
voyeur_unix_top_dirs = ['/home', '/Users']
#voyeur_unix_top_dirs = []
voyeur_win_top_dirs = ['C:/']
voyeur_dirs_wild = ["download", "downloads", "Download", "Downloads", "Scaricati"]
voyeur_unix_dirs_nowild = ["/tmp"]
voyeur_win_dirs_nowild = []

# MAX SIZE FILE TO CHECK BY SCAN
max_file_size = 52428800

# YARA RULES WHITELIST
yara_whitelist = ["powershell", "Misc_Suspicious_Strings", "SurtrStrings", "Surtr", "BASE64_table", "Big_Numbers0", "Big_Numbers1", "Big_Numbers2", "Big_Numbers3", "Big_Numbers4", "Big_Numbers5", "BLOWFISH_Constants", "Borland", "Chacha_128_constant", "Chacha_256_constant", "CRC16_table", "CRC32b_poly_Constant", "CRC32c_poly_Constant", "CRC32_poly_Constant", "CRC32_table", "cred_ff", "DES_Long", "DES_sbox", "ecc_order", "maldoc_getEIP_method_1", "maldoc_OLE_file_magic_number", "MD5_Constants", "PlugX", "ppaction", "Prime_Constants_long", "Qemu_Detection", "RIPEMD160_Constants", "SEH__vectored", "SHA1_Constants", "SHA2_BLAKE2_IVs", "SHA3_constants", "SHA512_Constants", "SipHash_big_endian_constants", "spreading_file", "Str_Win32_Http_API", "Str_Win32_Winsock2_Library", "System_Tools", "ThreadControl__Context", "url", "WHIRLPOOL_Constants", "win_mutex", "win_registry", "with_images", "without_attachments", "without_images", "without_urls", "with_urls"]

# HASH WHITELIST
hash_whitelist = []

# IP WHITELIST
ip_whitelist = []

# SUFFIX REPORT NAMES
yara_report_suffix = "yara"
hash_report_suffix = "hash"
syscall_report_suffix = "syscall"
