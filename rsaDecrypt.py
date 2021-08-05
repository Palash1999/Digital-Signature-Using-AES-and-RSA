# Palash Rathore - 2018173
def decrypt(d, n, m):
    ans = 1
    for i in range(1, d+1):
        ans = (ans * m) % n
    return ans
