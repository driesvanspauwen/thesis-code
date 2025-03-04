class Logger:
    log_file: object

    def __init__(self) -> None:
        self.log_file = open('emulation_log.txt', 'w')

    def log(self, message: str) -> None:
        self.log_file.write(message)

    def error(self, message: str) -> None:
        self.log_file.write('ERROR: ' + message)