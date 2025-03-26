import logging

class Logger:
    """
    A simple logging utility for managing log files and console output.

    Attributes:
        formatter (logging.Formatter): Defines the format of log messages.
    
    Methods:
        __init__(log_name: str, log_file_path: str | None, level: int = logging.INFO):
            Initializes the logger with a specified name, file path, and log level.
        
        get_logger() -> logging.Logger:
            Returns the logger instance for use in other parts of the application.
    """

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    def __init__(self, log_name: str, log_file_path: str | None, level: int = logging.INFO):
        """
        Initializes a Logger instance.

        Args:
            log_name (str): The name of the logger.
            log_file_path (str | None): The path to the log file. If None, logs to the console.
            level (int, optional): The logging level (default: logging.INFO).
        """
        self.__handler = logging.FileHandler(log_file_path) if log_file_path else logging.StreamHandler()
        self.__handler.setFormatter(self.formatter)

        self.__logger = logging.getLogger(log_name)
        self.__logger.setLevel(level)
        self.__logger.addHandler(self.__handler)

    def get_logger(self) -> logging.Logger:
        """
        Returns the configured logger instance.

        Returns:
            logging.Logger: The logger instance.
        """
        return self.__logger
