from __future__ import (
    annotations,
)

import hashlib
import hmac
from io import (
    BytesIO,
)
from typing import (
    Generic,
)

from btctoy.codec import (
    encode_base58_checksum,
)
from btctoy.crypto.prime import (
    is_prime,
)
from btctoy.crypto.types import (
    FieldElementT,
)

# Secp256k1 ECDSA parameters
# https://en.bitcoin.it/wiki/Secp256k1

EC_A = 0
EC_B = 7
EC_PRIME = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 2**0
G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def is_on_elliptic_curve(
    x: FieldElementT, y: FieldElementT, a: FieldElementT, b: FieldElementT
) -> bool:
    # TODO implémentation: doit renvoyer True si (x, y) est sur la courbe, False sinon
    return ((y ** 2) == (x ** 3 + a * x + b))


def hash160(s: bytes) -> bytes:
    """sha256 followed by ripemd160"""
    return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()


def hash256(s: bytes) -> bytes:
    """two rounds of sha256"""
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


class ModularFieldInteger:
    value: int
    prime: int

    def __init__(self, value: int, prime: int) -> None:
        if is_prime(prime) is False:
            raise ValueError(f"{prime} is not a prime integer")
        self.value = value % prime
        self.prime = prime

    def __repr__(self) -> str:
        return f"F_{self.prime}({self.value})"

    def __eq__(self, other: ModularFieldInteger) -> bool:
        if other is None:
            return False
        return (self.prime == other.prime) and (self.value == other.value)

    def __ne__(self, other: ModularFieldInteger) -> bool:
        # this should be the inverse of the == operator
        return (self == other) is False

    def __add__(self, other: ModularFieldInteger) -> ModularFieldInteger:
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        # TODO implementer l'operateur d'addition, stocker le résultat dans une variable "value"
        value = (self.value + other.value) % self.prime
        return self.__class__(value, self.prime)

    def __sub__(self, other: ModularFieldInteger) -> ModularFieldInteger:
        if self.prime != other.prime:
            raise TypeError("Cannot subtract two numbers in different Fields")
        # TODO implementer l'operateur de soustraction, stocker le résultat dans une variable "value"
        value = (self.value - other.value) % self.prime
        return self.__class__(value, self.prime)

    def __mul__(self, other: ModularFieldInteger) -> ModularFieldInteger:
        if self.prime != other.prime:
            raise TypeError("Cannot multiply two numbers in different Fields")
        # TODO implementer l'operateur de multiplication, stocker le résultat dans une variable "value"
        value = (self.value * other.value) % self.prime
        return self.__class__(value, self.prime)

    def __pow__(self, exponent: int) -> ModularFieldInteger:
        # TODO implementer l'operateur de puissance (exponentiation), stocker le résultat dans une variable "value"
        # utiliser pow(self.value, n, self.prime) qui calcule (self.value ** n) % self.prime de manière optimisée
        # calculer n à partir de exponent en utilisant le petit théorème de fermat qui nous dit que (a ** (p - 1) % p == 1)
        n = exponent % (self.prime - 1)
        value = pow(self.value, n, self.prime)
        return self.__class__(value, self.prime)

    def __truediv__(self, other: ModularFieldInteger) -> ModularFieldInteger:
        
        """
            THEOREME DE FERMAT 
            https://www.bibmath.net/dico/index.php?action=affiche&quoi=./f/fermatpetit.html        
        """
        if self.prime != other.prime:
            raise TypeError("Cannot divide two numbers in different Fields")
        # TODO implementer la division modulaire en utilisant le petit théorème de fermat qui nous dit que (a ** (p - 1) % p == 1)
        # cela implique que (1/a) = pow(a, p - 2, p)
        # combiner cela à la propriété (b/a) = b * (1/a)
        value = (self.value * pow(other.value, (self.prime - 2), self.prime)) % self.prime
        return self.__class__(value, self.prime)

    def __rmul__(self, coefficient: int) -> ModularFieldInteger:
        value = (self.value * coefficient) % self.prime
        return self.__class__(value=value, prime=self.prime)


class EllipcCurvePoint(Generic[FieldElementT]):
    x: FieldElementT
    y: FieldElementT
    a: FieldElementT
    b: FieldElementT

    def __init__(
        self,
        x: FieldElementT | None,
        y: FieldElementT | None,
        a: FieldElementT,
        b: FieldElementT,
    ) -> None:
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        # x being None and y being None represents the point at infinity
        # Check for that here since the equation below won't make sense
        # with None values for both.
        if self.x is None and self.y is None:
            return

        if self.x is None or self.y is None:
            raise ValueError("Coordinates should both be None, or both be FieldElement")

        if is_on_elliptic_curve(x, y, a, b) is False:
            raise ValueError(f"({x}, {y}) is not on the elliptic curve")

    def __eq__(self, other: EllipcCurvePoint[FieldElementT]) -> bool:
        return (
            self.x == other.x
            and self.y == other.y
            and self.a == other.a
            and self.b == other.b
        )

    def __ne__(self, other: EllipcCurvePoint[FieldElementT]) -> bool:
        # this should be the inverse of the == operator
        return not (self == other)

    def __repr__(self) -> str:
        if self.x is None:
            return "ECP(infinity)"
        elif isinstance(self.x, ModularFieldInteger):
            return f"ECP({self.x.value}, {self.y.value})_{ self.a.value}_{self.b.value}_F_{self.x.prime}"
        return f"ECP({self.x}, {self.y})_{self.a}_{self.b}".format(
            self.x, self.y, self.a, self.b
        )

    def __add__(
        self, other: EllipcCurvePoint[FieldElementT]
    ) -> EllipcCurvePoint[FieldElementT]:
        if self.a != other.a or self.b != other.b:
            raise TypeError(
                "Points {}, {} are not on the same curve".format(self, other)
            )
        # Case 0.0: self is the point at infinity, return other
        if self.x is None:
            return other
        # Case 0.1: other is the point at infinity, return self
        if other.x is None:
            return self

        # Case 1: self.x == other.x, self.y != other.y
        # Result is point at infinity
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        # TODO implémenter l'addition de points d'une courbe elliptique en suivant les instruction:

               # Case 2: self.x ≠ other.x
        # Formula (x3,y3)==(x1,y1)+(x2,y2)
        # s=(y2-y1)/(x2-x1)
        # x3=s**2-x1-x2
        # y3=s*(x1-x3)-y1
        if self.x != other.x:
            # TODO calculer x, y ici en appliquant les formules pour x3, y3
            s = (other.y - self.y) / (other.x -  self.x)
            x = s ** 2 - self.x - other.x
            y = s * (self.x - x) - self.y 
            return self.__class__(x, y, self.a, self.b)

        # Case 4: if we are tangent to the vertical line,
        # we return the point at infinity
        # note instead of figuring out what 0 is for each type
        # we just use 0 * self.x
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        # Case 3: self == other
        # Formula (x3,y3)=(x1,y1)+(x1,y1)
        # s=(3*x1**2+a)/(2*y1)
        # x3=s**2-2*x1
        # y3=s*(x1-x3)-y1
        if self == other:
            # TODO calculer x, y ici en appliquant les formules pour x3, y3
            s = (3 * self.x ** 2 + self.a) / (2 * self.y)
            x = s ** 2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient: int) -> EllipcCurvePoint[FieldElementT]:
        # Implementation of fast scalar product
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result


class S256Integer(ModularFieldInteger):
    def __init__(self, value: int, prime: int = EC_PRIME) -> None:
        if prime != EC_PRIME:
            raise ValueError(
                f"S256Integer only supports EC_PRIME={EC_PRIME:x} as prime"
            )
        super().__init__(value=value, prime=prime)

    def __repr__(self) -> str:
        return f"{self.value:064x}"

    def sqrt(self) -> ModularFieldInteger:
        return self ** ((EC_PRIME + 1) // 4)


A = S256Integer(EC_A)
B = S256Integer(EC_B)


class S256Point(EllipcCurvePoint[ModularFieldInteger]):
    def __init__(
        self,
        x: int | S256Integer | None,
        y: int | S256Integer | None,
        a: S256Integer = A,
        b: S256Integer = B,
    ) -> None:
        if a != A:
            raise ValueError(f"S256Integer only supports A={A} for a")
        if b != B:
            raise ValueError(f"S256Integer only supports B={B} for b")
        super().__init__(
            x=None if x is None else S256Integer(x) if isinstance(x, int) else x,
            y=None if y is None else S256Integer(y) if isinstance(x, int) else y,
            a=A,
            b=B,
        )

    def __repr__(self) -> str:
        if self.x is None:
            return "S256Point(infinity)"
        else:
            return f"S256Point({self.x}, {self.y})"

    def __rmul__(self, coefficient: int) -> S256Point:
        coef = coefficient % G_ORDER
        return super().__rmul__(coef)

    def verify(self, z: int, sig: Signature) -> bool:
        # TODO implementer la fonction
        # 1. By Fermat's Little Theorem, s_inv = pow(s, G_ORDER-2, G_ORDER)
        # u = z * s_inv % G_ORDER
        # v = r * s_inv % G_ORDER
        # Should return if x coordinate of u*G + v*P is equal to r, where P = self
        #s_inv = pow(sig.s, G_ORDER - 2, G_ORDER)
        #u = z * s_inv % G_ORDER
        #v = sig.r * s_inv % G_ORDER
        #total = u * G + v * self
        s_inv = pow(sig.s, G_ORDER - 2, G_ORDER)
        # u = z / s
        u = z * s_inv % G_ORDER
        # v = r / s
        v = sig.r * s_inv % G_ORDER
        # u*G + v*P should have as the x coordinate, r
        total = u * G + v * self
     
        return total.x.value == sig.r
    
    def sec(self, compressed: bool = True) -> bytes:
        """returns the binary version of the SEC format"""
        # TODO implementer la fonction
        if compressed:
            # if compressed, starts with b'\x02' if self.y.value is even, b'\x03' if self.y is odd
            # then self.x.value
            # remember, you have to convert self.x.value and self.y.value to binary (some_integer.to_bytes(32, 'big'))
            if self.y.value % 2 == 0:
                return b"\x02" + self.x.value.to_bytes(32, "big")
            else:
                return b"\x03" + self.x.value.to_bytes(32, "big")
        else:
            return b"\x04" + self.x.value.to_bytes(32, "big") + self.y.value.to_bytes(32, "big")

    def hash160(self, compressed: bool = True) -> bytes:
        return hash160(self.sec(compressed))

    def address(self, compressed: bool = True, testnet: bool = False) -> str:
        """Returns the address string"""
        # TODO implementer la fonction
        h160 =  self.hash160(compressed)
        if testnet:
            prefix = b"\x6f"
        else:
            prefix = b"\x00"
        return encode_base58_checksum(prefix + h160)

    @classmethod
    def parse(cls, sec_bin: bytes) -> S256Point:
        """returns a Point object from a SEC binary (not hex)"""
        # TODO completer la fonction qui décode ce qui est encodé dans sec()
        # Décode ce qui est encodé dans sec()
        if sec_bin[0] == 4:
            # Cas où sec_bin commence par 0x04 (clé publique non compressée)
            x = int.from_bytes(sec_bin[1:33], "big")
            y = int.from_bytes(sec_bin[33:65], "big")
            return S256Point(x=x, y=y)
        else:
            # Cas où sec_bin commence par 0x02 ou 0x03 (clé publique compressée)
            bip = sec_bin[0] == 2
            x = S256Integer(int.from_bytes(sec_bin[1:], "big"))
            alpha = x ** 3 + S256Integer(EC_B)
            beta = alpha.sqrt()
            # Choix entre e et o en fonction de la parité de beta.value
            if beta.value % 2 == 0:
                e, o = beta.value, S256Integer(EC_PRIME - beta.value)
            else:
                o, e = beta.value, S256Integer(EC_PRIME - beta.value)
            # Retourne la S256Point correspondante
            if bip:
                return S256Point(x, e)
            else:
                return S256Point(x, o)

        

G = S256Point(
    G_X,
    G_Y,
)


class Signature:
    r: int
    s: int

    def __init__(self, r: int, s: int) -> None:
        self.r = r
        self.s = s

    def __repr__(self) -> str:
        return f"Signature(r={self.r}, s={self.s})"

    def der(self) -> bytes:
        rbin = self.r.to_bytes(32, byteorder="big")
        # remove all null bytes at the beginning
        rbin = rbin.lstrip(b"\x00")
        # if rbin has a high bit, add a \x00
        if rbin[0] & 0x80:
            rbin = b"\x00" + rbin
        result = bytes([2, len(rbin)]) + rbin  # <1>
        sbin = self.s.to_bytes(32, byteorder="big")
        # remove all null bytes at the beginning
        sbin = sbin.lstrip(b"\x00")
        # if sbin has a high bit, add a \x00
        if sbin[0] & 0x80:
            sbin = b"\x00" + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin: bytes) -> Signature:
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), "big")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), "big")
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)


class PrivateKey:
    secret: int
    point: S256Point

    def __init__(self, secret: int) -> None:
        self.secret = secret
        self.point = secret * G

    def hex(self) -> str:  # noqa: A003
        return f"{self.secret:064x}"

    def sign(self, z: int) -> Signature:
        k = self.deterministic_k(z)
        # Calcul de r, qui est la coordonnée x du point résultant k*G
        r = (k * G).x.value
        # Calcul de l'inverse de k : 1/k = pow(k, N-2, N)
        k_inv = pow(k, G_ORDER - 2, G_ORDER)
        # Calcul de s : (z + r * secret) / k % G_ORDER
        s = (z + r * self.secret) * k_inv % G_ORDER
        # Si s est plus grand que G_ORDER / 2, on le remplace par G_ORDER - s
        if s > G_ORDER / 2:
            s = G_ORDER - s
        # Retourne une instance de Signature avec les valeurs de r et s calculées
        return Signature(r, s)

    def deterministic_k(self, z: int) -> int:
        k = b"\x00" * 32
        v = b"\x01" * 32
        if z > G_ORDER:
            z -= G_ORDER
        z_bytes = z.to_bytes(32, "big")
        secret_bytes = self.secret.to_bytes(32, "big")
        s256 = hashlib.sha256
        k = hmac.new(k, v + b"\x00" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b"\x01" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, "big")
            if candidate >= 1 and candidate < G_ORDER:
                return candidate
            k = hmac.new(k, v + b"\x00", s256).digest()
            v = hmac.new(k, v, s256).digest()

    def wif(self, compressed: bool = True, testnet: bool = False) -> str:
        # convert the secret from integer to a 32-bytes in big endian using num.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, "big")
        # prepend b'\xef' on testnet, b'\x80' on mainnet
        if testnet:
            prefix = b"\xef"
        else:
            prefix = b"\x80"
        # append b'\x01' if compressed
        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        # encode_base58_checksum the whole thing
        return encode_base58_checksum(prefix + secret_bytes + suffix)
