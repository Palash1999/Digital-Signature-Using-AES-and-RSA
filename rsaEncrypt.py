# Palash Rathore - 2018173
def encrypt(e, n, m):
    ans = 1
    for i in range(1, e+1):
        ans = (ans * m) % n
    return ans
