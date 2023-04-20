# this project will check your project via file text , you can have multiple passswords but need to split by white space

import requests
import hashlib
import sys
import re


def request_api_data(query_char):
    url = 'http://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching : {res.status_code}, check the api and try again')

    return res


def get_password_leak_count(hashes, hash_to_check):  # check hashes to check by loop through all hashes
    hashes = (line.split(':') for line in hashes.text.splitlines())  # tuple , list comprehension
    for h, count in hashes:  # after split hashes become 2 part
        if h == hash_to_check:
            return count

    return 0


# this is my old function that check via input in terminal
'''
def pwned_api_check(password):
    # check if password exist in API response
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first = sha1_password[:5]
    tail = sha1_password[5:]
    response = request_api_data(first)
    return get_password_leak_count(response, tail)
'''

with open('pass_test.txt', mode='r') as my_file:
    list_passwords = my_file.read().split(' ')


## this is my new function that also check for password validation
def pwned_api_check(password):
    # check password validation - at least 8 characters - # contain any letter, digit and @$#%
    password_valid = re.compile(r"[a-zA-Z0-9@$#%]{8,}")
    validation = password_valid.fullmatch(password)

    # check if password exist in API response
    if validation:
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first = sha1_password[:5]
        tail = sha1_password[5:]
        response = request_api_data(first)
        return get_password_leak_count(response, tail)
    else:
        return -1



def main(argvs):
    for password in argvs:
        count = pwned_api_check(password)
        if count != -1:
            if count:
                print(f'{password} was found {count} times ....!! Be careful')
            else:
                print(f'{password} not found!! Carry on!')
        else:
            print(f'your password {password} not met our requirements')

    return 'Done checking!!'


if __name__ == '__main__':
    sys.exit(main(list_passwords))
