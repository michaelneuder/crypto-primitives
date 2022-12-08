from curve import CurveFp
from point import Point


secp256k1 = CurveFp(
    name="secp256k1",
    A=0x0000000000000000000000000000000000000000000000000000000000000000,
    B=0x0000000000000000000000000000000000000000000000000000000000000007,
    P=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    oid=[1, 3, 132, 0, 10]
)

print("general elliptic curve = y^2 = x^3 + Ax + B % P.")
print("secp256k1 curve= y^2 = x^3 + 7.")
print("prime of curve in decimal {:0d}".format(secp256k1.P))

res3 = secp256k1.y(3, isEven=False)
print("sep256k1. when x=3, y={:0d}".format(res3))

point = Point(
    x=3,
    y=res3,
)

print("confirming that point (x,y)=({}, {}) is on curve: {}".format(3, res3, secp256k1.contains(point)))