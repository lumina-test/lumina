import sys

if sys.version_info < (3,):
    # get the ascii code of a character (for python.2x)
    compat_ord = ord
else:
    # in python3.x, we don't need to do this
    def compat_ord(char):
        return char

def bytes_to_int(address):
    """ Convert a byte array to an integer

    Args:
        address (bytes): The byte array to convert

    Returns:
        int: The integer representation of the byte array
    """
    ret_value = 0
    for b in address:
        ret_value = (ret_value << 8) + compat_ord(b)
    return ret_value
