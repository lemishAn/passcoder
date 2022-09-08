import math
from rsa import common
import re
import random



primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
          101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
          199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
          317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
          443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571,
          577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
          701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
          839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977,
          983, 991, 997]
#


def isPrime(n):
    k = 0
    temp = n - 1
    while temp % 2 == 0:
        temp = temp // 2
        k += 1
    else:
        m = temp
    for a in primes:
        x = [pow(a, m * (2 ** i), n) for i in range(0, k)]
        if pow(a, m, n) != 1 and none_in_x_is_n(x, n - 1):
            return False
        elif pow(a, m, n) == 1 or not none_in_x_is_n(x, n - 1):
            continue

    return True

def generate_a_prime_number(num_of_bits):
    while 1:
        num = random.getrandbits(num_of_bits)
        if isPrime(num):
            return num
        else:
            continue

def sqrt_p_3_mod_4(a, p):
    r = pow(a, (p + 1) // 4, p)
    return r

def sqrt_p_5_mod_8(a, p):
    d = pow(a, (p - 1) // 4, p)
    r =0
    if d == 1:
        r = pow(a, (p + 3) // 8, p)
    elif d == p - 1:
        r = 2 * a * pow(4 * a, (p - 5) // 8, p) % p

    return r

def Legendre(a, p):
    return pow(a, (p - 1) / 2, p)

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, y, x = egcd(b % a, a)
        return gcd, x - (b // a) * y, y

def none_in_x_is_n(x, n):
    for i in x:
        if i == n:
            return False
    return True

#def __convert2int(byte_str):
#    return int.from_bytes(byte_str, "big", signed=False)
#
#def __convert2byte(number):
#    bytes_required = max(1, math.ceil(chifr.bit_length() / 8))
#    raw = number.to_bytes(bytes_required, "big")
#    return raw.decode("utf-8").encode("utf-8")
    

def __generate_rab_number__(num_of_bites):
    while True:
        number = generate_a_prime_number(num_of_bites)
        if number % 4 == 3: return number

def generate_keys(num_of_bites = 128):
    p = __generate_rab_number__(num_of_bites)
    q = __generate_rab_number__(num_of_bites)
    n = p*q
    return (str(n).encode('utf-8'),
            (str(p).encode('utf-8'),str(q).encode('utf-8')))

def encryption(plaintext, n):
    plaintext = padding(plaintext)
    return plaintext ** 2 % n

def padding(plaintext):
    binary_str = bin(plaintext)     
    output = binary_str + binary_str[-2:] 
    return int(output, 2)       

def decryption(a, p, q):
    n = p * q
    r, s = 0, 0
    if p % 4 == 3:
        r = sqrt_p_3_mod_4(a, p)
    elif p % 8 == 5:
        r = sqrt_p_5_mod_8(a, p)
    if q % 4 == 3:
        s = sqrt_p_3_mod_4(a, q)
    elif q % 8 == 5:
        s = sqrt_p_5_mod_8(a, q)

    gcd, c, d = egcd(p, q)
    x = (r * d * q + s * c * p) % n
    y = (r * d * q - s * c * p) % n
    lst = [x, n - x, y, n - y]

    plaintext = choose(lst)
    string = bin(plaintext)
    string = string[:-2]
    plaintext = int(string, 2)

    return plaintext


def choose(lst):
    for i in lst:
        binary = bin(i)
        append = binary[-2:]   
        binary = binary[:-2]  
        if append == binary[-2:]:
            return i
    return

if __name__ == "__main__":
    p = '197014045887093073932835008497823916631'
    q = '172130493496519272575530221657013852019'
    passwd = input('pass').encode('utf-8')
    dechifr = decryption(int(passwd), int(p), int(q))
    bytes_required = max(1, math.ceil(dechifr.bit_length() / 8))
    raw = dechifr.to_bytes(bytes_required, "big")
    print(raw)
