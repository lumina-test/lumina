import logging

def config_stream_handler(logger):
    """ Configure stream handler

    Args:
        logger (logging.Logger): Logger object

    Returns:
        N/A
    """
    logger.setLevel(logging.INFO)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter('%(name)-18s: %(levelname)-8s %(message)s'))
    logger.addHandler(console)

def config_file_handler(logger, log_file, no_format=False):
    """ Configure file handler

    Args:
        logger (logging.Logger): Logger object
        log_file (str): Log file path
        no_format (bool): If True, do not format log messages (default: False)

    Returns:
        N/A
    """
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(log_file, mode="w")
    if no_format == False:
        file_handler.setFormatter(logging.Formatter('%(name)-18s: %(levelname)-8s %(message)s'))
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)
