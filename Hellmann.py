import hashlib as hl                    # sha1
import secrets as rnd                   # randbelow, choice
import os, sys                          # output and logging
import numpy as np, scipy.stats as sp   # stats calculations
import matplotlib.pyplot as plt         # plotting

n = 16
n_bytes = n // 8
pad_w = 128 - n
pad_w_bytes = pad_w // 8
N = 10000


# Function to generate <bits>-bit value
def generate_bits(bits=256):
    return rnd.token_bytes(bits // 8)

def generate(bytes):
    return rnd.token_bytes(bytes)

# to bits cnvrt
def bytearr_to_bitstr(bytestr):
    return ''.join(format(b, '08b') for b in bytestr)

# hash
def h_n_bytes(byts):
    return hl.sha1(byts).digest()[-n_bytes:]


# ================== Атака пошуку прообразу ==================

def find_preimage(L, p_table, hash_val):
    def R(x):
        return p_table[1] + x    

    y = hash_val

    j_found = -1
    for j in range(L):
        # Check all i for xiL == y
        if y in p_table[0]:
            j_found = j
            break

        # Next itr
        y = h_n_bytes(R(y))
    
    if j_found != -1:
        x = p_table[0][y]
        for _ in range(L - j_found - 1):
            x = h_n_bytes(R(x))
        return [R(x), True]

    # Error
    return [None, False]

def check_preimage(preimage, h_val):
    if h_n_bytes(preimage) == h_val:
        return True
    
    return False

# ============================================================

# ================== Атака 1 (одна таблиця) ==================

# ------------- Parallel generation of the table -------------

from concurrent.futures import ProcessPoolExecutor

def generate_table_parallel(task, K, *parameters):
    with ProcessPoolExecutor() as executor:
        d = dict(executor.map(task, range(K), *parameters))
        # print("Finished mapping")
        return d

def R(r, x):
    return r + x

def append_value(_, L, r):
    x0 = generate(n_bytes) 
    value = x0
    for _ in range(L):
        value = h_n_bytes(R(r, value))
    return (value, x0)

def gen_pre_table_parallel(K, L):
    r = generate(pad_w_bytes)

    # print("Started parallel")
    X = generate_table_parallel(append_value, K, [L]*K, [r]*K)
        
    return (X, r)

# ------------------------------------------------------------

# K_arr_1 = [2**20, 2**22, 2**24]
# L_arr_1 = [2**10, 2**11, 2**12]

K_arr_1 = [2**10, 2**12, 2**14]
L_arr_1 = [2**5, 2**6, 2**7]

def launch_attacks_type1():
    atk1_results = {}

    for K in K_arr_1:
        for L in L_arr_1:
            # [<not found>, <fake>, <true>]
            print(f"{K}, {L}: started")
            run_result = [0, 0, 0]
            p_table= gen_pre_table_parallel(K, L)
            print(f"{K}, {L}: Table ready!")
            for _ in range(N):
                value = generate(32)
                h_val = h_n_bytes(value)

                preimage, found = find_preimage(L, p_table, h_val)

                if found:
                    if h_n_bytes(preimage) == h_val:
                        run_result[2] += 1
                    else:
                        run_result[1] += 1
                else:
                    run_result[0] += 1
            
            atk1_results[(K, L)] = run_result

            print(f"{K}, {L} results: {run_result}")
    return atk1_results



# ================== Атака 2 (K таблиць) =====================

# ------------- Parallel generation of K tables --------------

def gen_pre_table(K, L):
    r = generate(pad_w_bytes)
    def R(x):
        return r + x

    X = {}

    for _ in range(K):
        x0 = generate(n_bytes) 
        value = x0
        for _ in range(L):
            value = h_n_bytes(R(value))
        X[value] = x0
    
    return (X, r)

def generate_table_instance(_, K, L):
    return gen_pre_table_parallel(K, L)

def generate_K_tables_parallel(K, L):
    print("Started table generation")
    with ProcessPoolExecutor() as executor:
        res = list(executor.map(gen_pre_table, [K]*K, [L]*K))
        print("Finished table generation")
        return res

# ------------------------------------------------------------

# K_arr_2 = [2**10, 2**11, 2**12]
# L_arr_2 = [2**10, 2**11, 2**12]

K_arr_2 = [2**5, 2**6, 2**7]
L_arr_2 = [2**5, 2**6, 2**7]

def launch_attacks_type2():
    atk2_results = {}

    for K in K_arr_2:
        for L in L_arr_2:
            # [<not found>, <true>]
            print(f"{K}, {L}: started")
            run_result = [0, 0]

            Tables = generate_K_tables_parallel(K, L)
            print(f"{K}, {L}: Tables ready!")

            for i in range(N):
                print(i)
                value = generate_bits(256)
                h_val = h_n_bytes(value)

                with ProcessPoolExecutor() as executor:
                    preimages = list(executor.map(find_preimage, [L]*K, Tables, [h_val]*K))
                    

                    run_result[0] += 1
                    for preimage, found in preimages:
                        if found and h_n_bytes(preimage) == h_val:
                            run_result[1] += 1
                            run_result[0] -= 1
                            break

            print(f"{K}, {L} results: {run_result}")
                            


    return atk2_results

# ====================== Test field ==========================

def main():
    K = 2**5
    L = 2**5
    # print("K\tL")
    # print(K_test, L_test)

    # # value = generate_bits(256)
    # # h_val = h_n_bytes(value)

    # # print(h_val)

    # data = generate_K_tables_parallel(K_test, L_test)
    # print(len(data))
    # print("Tables rdy!")
    # # print(X)
    # # preimage, found = find_preimage(L_test, X, r, h_val)

    # # if found:
    # #     print(preimage)
    # #     print(h_n_bytes(preimage))
    # # else:
    # #     print("No succ? :(")

    Tables = generate_K_tables_parallel(K, L)
    print(f"{K}, {L}: Tables ready!")
    print(Tables)

    value = generate_bits(256)
    h_val = h_n_bytes(value)

    with ProcessPoolExecutor() as executor:
        preimages = list(executor.map(find_preimage, [L]*K, Tables, [h_val]*K))

        for preimage, found in preimages:
            if found:
                print(f"Found: {preimage}")
                if h_n_bytes(preimage) == h_val:
                    print("preimage!")
                    break
            else:
                print("Not found")

from datetime import datetime         # execution time
    
if __name__ == '__main__':
    start = datetime.now()
    Results1 = launch_attacks_type1()
    print(Results1)

    # Results2 = launch_attacks_type2()
    # print(Results2)
    
    # main()
    end = datetime.now()

    print(f"Execution time: {end - start}")