class Logger():
    def __init__(self, log_file):
        self.log_file = log_file
        self.clear_log()

    def clear_log(self):
        with open(self.log_file, 'w') as f:
            f.truncate(0)  # Clears the file content

    def log(self, message):
        with open(self.log_file, 'a') as f:
            f.write(message + '\n')
