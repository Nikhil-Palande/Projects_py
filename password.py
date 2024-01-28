import requests
import hashlib
import sys


# This function creates an api that receive request from the site
def request_api(pasw):
    url = 'https://api.pwnedpasswords.com/range/' + pasw
    res = requests.get(url)
    # res.status_code is used to check security of data being sent
    if res.status_code != 200:
        raise RuntimeError(f'Error in response:{res.status_code}')
    return res


# In read_res function we get the list of tail combinations that have the same first 5 hashes
# then we separate the last hashes and counts of that combinations using split() and splitlines()
# We take response from api and the tail of our password hashcode as argument
# If the tail hash and ou hash match we return the count which we separated in tuple
# If matched we return count if not we return zero
def check_leaks(value, tail_char):
    # splitlines() is used to split multi-line string into a list of sting
    # split('separator) is used to separate a string from given seperator
    # whitespace is default seperator if not given any
    separate = (line.split(':') for line in value.text.splitlines())
    for h, count in separate:
        if h == tail_char:
            return count
    return 0


# Here we take password and convert the password into SHA1 hash code
# then we separate first 5 hash code using list slicing and call the request_api function by passing first 5 hash codes
# We store the response from the api in a variable that is passed to check_leaks function
def passwrd(password):
    sha1pswd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1pswd[:5], sha1pswd[5:]
    print(first5, tail)

    # request_api() returns the tail combinations associated with the first 5 hash codes
    response = request_api(first5)
    return check_leaks(response, tail)


# Main function to check our passwords
def main(args):
    for i in args:
        check = passwrd(i)
        print(f"Checking if {i} was pawned")
        if check:
            print(f"{i} was found {check} times")
        else:
            print(f"{i} was not found, Good password")


main(sys.argv[1:])
