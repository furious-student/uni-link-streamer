import ipaddress
from typing import Tuple, Union, IO


# return a tuple where the first element is integer if the conversion was successful or None if it was not.
# the second argument is the code:
#   0 -> OK
#   1 -> Not a number
#   0 -> Not a number from given range
def as_number_from_range(target: str, lower: int, upper: int) -> Tuple[Union[None, int], int]:
    try:
        number = int(target)
        if lower <= number <= upper:
            return number, 0
        else:
            return number, 1
    except ValueError:
        return None, 1


def while_not_valid_number(input_message: str, lower: int, upper: int) -> int:
    number = input(input_message)
    result = as_number_from_range(target=number, lower=lower, upper=upper)
    while not result[1] == 0:
        print(f"Input must be integer from range <{lower};{upper}> but is '{number}'")
        number = input(input_message)
        result = as_number_from_range(target=number, lower=lower, upper=upper)
    return result[0]


def open_file(path: str, mode: str) -> Union[None, IO]:
    try:
        return open(file=path, mode=mode)
    except FileNotFoundError:
        print(f">> Error: The file '{path}' does not exist.")
    except PermissionError:
        print(f">> Error: You don't have permission to access '{path}'.")
    except IsADirectoryError:
        print(f">> Error: '{path}' is a directory. Please provide a file path.")
    except Exception as e:
        print(f">> An unexpected error occurred: {e}")
    return None


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def while_not_valid_ip(input_message: str = "Input IP: ") -> str:
    ip = input(input_message)
    result = is_valid_ip(ip=ip)
    while result is False:
        print(f"Input must be a valid IP address, but is '{ip}'")
        ip = input(input_message)
        result = is_valid_ip(ip=ip)
    return ip
