sleep_thread_restart = 10
sleep_thread_socket_restart = 60

management_host = "127.0.0.1"
management_port = 5000

linux_dir_exclusions = ["/proc/", "/dev/", "/sys/", "/usr/src/linux/", "/opt/yara", "/var/lib/apt/lists/"]
extension_exclusions = [".yar", ".yara", ".h", ".pem", ".crt", ".dat", ".dat-old", ".cache", ".crash", ".db", ".log"]
voyeur_dirs_wild = ["download", "downloads", "Download", "Downloads", "Scaricati"]
voyeur_dirs_nowild = ["/tmp"]

buf_size_calc_hash = 65536
max_file_size = 52428800

mac_top_dirs = []
