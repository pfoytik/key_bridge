def is_prime(n):
    """Check if a number n is prime using the Miller-Rabin test (pure math)."""
    if n < 2:
        return False
    if n in (2, 3, 5, 7):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as (2^s) * d where d is odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    def miller_rabin_witness(a):
        """Perform the Miller-Rabin test for a given base a."""
        x = pow(a, d, n)  # Compute a^d % n
        if x == 1 or x == n - 1:
            return True  # Likely prime

        for _ in range(s - 1):
            x = pow(x, 2, n)  # Compute x^2 % n
            if x == n - 1:
                return True  # Likely prime
        return False  # Composite

    # Test small bases
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if a >= n:
            break
        if not miller_rabin_witness(a):
            return False  # Composite

    return True  # Prime with high probability


# SECP256K1 Order Constant
secp256k1_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# Check if it's prime
print(is_prime(secp256k1_order))  # Expected output: True
