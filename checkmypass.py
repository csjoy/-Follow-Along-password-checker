import hashlib
import requests


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + str(query_char)
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code}, check the api and try again")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hash = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hash:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha1_first5, sha1_remaining = sha1_password[:5], sha1_password[5:]
    response = request_api_data(sha1_first5)
    return get_password_leaks_count(response, sha1_remaining)


def main(args):
    for password in args:
        if len(password) > 1:
            count = pwned_api_check(password)
            if count:
                print(
                    f"{password} was found {count} times... you should probably change your password")
            else:
                print(f"{password} was NOT found. Carry on!")
    return "Done!\nPlease remove 'password.txt' file for safety reason."


if __name__ == '__main__':
    try:
        with open('password.txt') as pass_file:
            pass_list = pass_file.read().replace("\n", " ").replace("\r", " ").split(" ")
            print(main(pass_list))
    except FileNotFoundError:
        print("File not found!")
        print("Please create a file name 'password.txt' and put all your password to check if that password ever breached before.")
    except IOError:
        print("IO error!")
        print("Please try again later or use different computer.")
    except:
        print("Something went wrong!")
