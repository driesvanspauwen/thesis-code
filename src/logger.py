import os
import datetime

class Logger:
    def __init__(self, log_file, debug: bool = True, log_time: bool = False, max_size_bytes=10*1024*1024, backup_count=5):
        self.debug = debug
        self.log_time = log_time
        self.log_file = log_file
        self.max_size = max_size_bytes
        self.backup_count = backup_count
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        self.clear_log()

    def clear_log(self):
        with open(self.log_file, 'w') as f:
            f.truncate(0)

    def rotate_logs(self):
        if not os.path.exists(self.log_file):
            return
        if os.path.getsize(self.log_file) < self.max_size:
            return
        # Remove the oldest backup if it exists
        oldest = f"{self.log_file}.{self.backup_count}"
        if os.path.exists(oldest):
            os.remove(oldest)
        # Shift other backups
        for i in range(self.backup_count - 1, 0, -1):
            src = f"{self.log_file}.{i}"
            dst = f"{self.log_file}.{i + 1}"
            if os.path.exists(src):
                os.rename(src, dst)
        # Rename current log to .1
        os.rename(self.log_file, f"{self.log_file}.1")

    def log(self, message):
        if self.debug:
            if self.log_time:
                # Only time, not date
                timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                formatted_message = f"[{timestamp}] {message}"
            else:
                formatted_message = message
            
            self.rotate_logs()
            with open(self.log_file, 'a') as f:
                f.write(formatted_message + '\n')