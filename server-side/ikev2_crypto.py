# code based on https://github.com/aatlasis/yIKEs/blob/main/crypto.py

import struct
import enum
import hashlib ,hmac, secrets
from Crypto.Cipher import AES, DES3
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class TypeEnum(enum.IntEnum):
    @classmethod
    def _missing_(cls, value):
        obj = int.__new__(cls, value)
        obj._name_ = f'{cls.__name__}_{value}'
        obj._value_ = value
        return obj

class DhId(TypeEnum):
    DH_NONE = 0
    DH_1 = 1
    DH_2 = 2
    DH_5 = 5
    DH_14 = 14
    DH_15 = 15
    DH_16 = 16
    DH_17 = 17
    DH_18 = 18
    DH_19 = 19
    DH_20 = 20
    DH_21 = 21
    DH_22 = 22
    DH_23 = 23
    DH_24 = 24
    DH_25 = 25
    DH_26 = 26
    DH_27 = 27
    DH_28 = 28
    DH_29 = 29
    DH_30 = 30
    DH_31 = 31
    DH_32 = 32

class PrfId(TypeEnum):
    PRF_HMAC_MD5 = 1
    PRF_HMAC_SHA1 = 2
    PRF_HMAC_TIGER = 3
    PRF_AES128_XCBC = 4
    PRF_HMAC_SHA2_256 = 5
    PRF_HMAC_SHA2_384 = 6
    PRF_HMAC_SHA2_512 = 7
    PRF_AES128_CMAC = 8

#ikev1
class HashId_1(TypeEnum):
    MD5 = 1
    SHA = 2
    TIGER = 3
    SHA2_256 = 4
    SHA2_384 = 5
    SHA2_512 = 6

class IntegId(TypeEnum):
    AUTH_NONE = 0
    AUTH_HMAC_MD5_96 = 1
    AUTH_HMAC_SHA1_96 = 2
    AUTH_DES_MAC = 3
    AUTH_KPDK_MD5 = 4
    AUTH_AES_XCBC_96 = 5
    AUTH_HMAC_MD5_128 = 6
    AUTH_HMAC_SHA1_160 = 7
    AUTH_AES_CMAC_96 = 8
    AUTH_AES_128_GMAC = 9
    AUTH_AES_192_GMAC = 10
    AUTH_AES_256_GMAC = 11
    AUTH_HMAC_SHA2_256_128 = 12
    AUTH_HMAC_SHA2_384_192 = 13
    AUTH_HMAC_SHA2_512_256 = 14

#ikev1
class IntegId_1(TypeEnum):
    AUTH_NONE = 0
    AUTH_HMAC_MD5 = 1
    AUTH_HMAC_SHA1 = 2
    AUTH_DES_MAC = 3
    AUTH_KPDK = 4
    AUTH_HMAC_SHA2_256 = 5
    AUTH_HMAC_SHA2_384 = 6
    AUTH_HMAC_SHA2_512 = 7
    AUTH_HMAC_RIPEMD = 8
    AUTH_AES_XCBC_MAC = 9
    AUTH_SIG_RSA = 10
    AUTH_AES_128_GMAC = 11
    AUTH_AES_192_GMAC = 12
    AUTH_AES_256_GMAC = 13

class EncrId(TypeEnum):
    ENCR_DES = 2
    ENCR_3DES = 3
    ENCR_RC5 = 4
    ENCR_IDEA = 5
    ENCR_CAST = 6
    ENCR_BLOWFISH = 7
    ENCR_3IDEA = 8
    ENCR_DES_IV32 = 9
    ENCR_NULL = 11
    ENCR_AES_CBC = 12
    ENCR_AES_CTR = 13
    ENCR_AES_CCM_8 = 14
    ENCR_AES_CCM_12 = 15
    ENCR_AES_CCM_16 = 16
    ENCR_AES_GCM_8 = 18
    ENCR_AES_GCM_12 = 19
    ENCR_AES_GCM_16 = 20
    ENCR_NULL_AUTH_AES_GMAC = 21
    ENCR_CAMELLIA_CBC = 23
    ENCR_CAMELLIA_CTR = 24
    ENCR_CAMELLIA_CCM_8 = 25
    ENCR_CAMELLIA_CCM_12 = 26
    ENCR_CAMELLIA_CCM_16 = 27
    ENCR_CHACHA20_POLY1305 = 28
    ENCR_AES_CCM_8_IIV = 29
    ENCR_AES_GCM_16_IIV = 30
    ENCR_CHACHA20_POLY1305_IIV = 31

#ikev1
class EncrId_1(TypeEnum):
    DES_CBC = 1
    IDEA_CBC = 2
    BLOWFISH_CBC = 3
    RC5_R16_B64_CBC = 4
    _3DES_CBC = 5
    CAST_CBC = 6
    AES_CBC = 7
    CAMELLIA_CBC = 8

class Cipher:
    CIPHERS = {
        EncrId.ENCR_3DES: (DES3, DES3.MODE_CBC, 8),
        EncrId.ENCR_AES_CBC: (AES, AES.MODE_CBC, 16),
        EncrId.ENCR_AES_CTR: (AES, AES.MODE_CTR, 16),
        EncrId.ENCR_AES_CCM_8: (AES, AES.MODE_CCM, 16),
        EncrId.ENCR_AES_CCM_12: (AES, AES.MODE_CCM, 16),
        EncrId.ENCR_AES_CCM_16: (AES, AES.MODE_CCM, 16),
        EncrId.ENCR_AES_GCM_8: (AES, AES.MODE_GCM, 16),
        EncrId.ENCR_AES_GCM_12: (AES, AES.MODE_GCM, 16),
        EncrId.ENCR_AES_GCM_16: (AES, AES.MODE_GCM, 16),
    }

    def __init__(self, transform, keylen):
        assert transform in self.CIPHERS
        self.cipher, self.aes_mode, self.block_size = self.CIPHERS[transform]
        self.keylen = 192 if transform == EncrId.ENCR_3DES else keylen

    @property
    def key_size(self):
        return self.keylen // 8

def generate_iv(block_size):
    return secrets.token_bytes(block_size)

class DHType(TypeEnum):
    DH_NOT_IMPLEMENTED = 0
    DH_MODP = 1
    DH_ECDH = 2
    DH_X25519 = 3

DH_GROUPS = {
    DhId.DH_1: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF, 2, 96)),
    DhId.DH_2: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF, 2, 128)),
    DhId.DH_5: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF, 2, 192)),
    DhId.DH_14: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF, 2, 256)),
    DhId.DH_15: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF, 2, 384)),
    DhId.DH_16: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF, 2, 512)),
    DhId.DH_17: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF, 2, 768)),
    DhId.DH_18: (DHType.DH_MODP, (0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF, 2, 1024)),
    DhId.DH_19: (DHType.DH_ECDH, ec.SECP256R1()), #(0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF, (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5, -3), 32),
    DhId.DH_20: (DHType.DH_ECDH, ec.SECP384R1()), #(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF, (0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F, -3), 48),
    DhId.DH_21: (DHType.DH_ECDH, ec.SECP521R1()), #(0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, (0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650, -3), 66),
    #DhId.DH_22: (DHType.DH_NOT_IMPLEMENTED, (0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371, 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5, 128)),
    #DhId.DH_23: (DHType.DH_NOT_IMPLEMENTED, (0xAD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F, 0xAC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA, 256)),
    #DhId.DH_24: (DHType.DH_NOT_IMPLEMENTED, (0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597, 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659, 256)),
    DhId.DH_25: (DHType.DH_ECDH, ec.SECP192R1()), #(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF, (0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF101207192B95FFC8DA78631011ED6B24CDD573F977A11E794811, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC), 24),
    DhId.DH_26: (DHType.DH_ECDH, ec.SECP224R1()), #(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001, (0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE), 28),
    #DhId.DH_27: (0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF, (0x0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD, 0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43), 28),
    DhId.DH_28: (DHType.DH_ECDH, ec.BrainpoolP256R1), #(0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377, (0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997, 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9), 32),
    DhId.DH_29: (DHType.DH_ECDH, ec.BrainpoolP384R1), #(0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53, (0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315, 0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826), 48),
    DhId.DH_30: (DHType.DH_ECDH, ec.BrainpoolP512R1), #(0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3, (0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F8227DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892, 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA), 64),
    DhId.DH_31: (DHType.DH_X25519, x25519),
}

def ec_add(P, Q, l, p, a):
    if P == 0:
        return Q
    if P == Q:
        z = (3*(P>>l)*(P>>l)+a) * pow(2*(P&(1<<l)-1), p-2, p)
    else:
        z = ((Q&(1<<l)-1) - (P&(1<<l)-1)) * pow((Q>>l)-(P>>l), p-2, p)
    x = (z*z - (P>>l) - (Q>>l)) % p
    return x<<l | (z*((P>>l)-x) - (P&(1<<l)-1)) % p

def ec_mul(P, l, i, p, a):
    r = 0
    while i > 0:
        if i & 1:
            r = ec_add(r, P, l<<3, p, a)
        i, P = i>>1, ec_add(P, P, l<<3, p, a)
    return r

class Prf:
    DIGESTS_1 = {
        HashId_1.MD5: (hashlib.md5, 16),
        HashId_1.SHA: (hashlib.sha1, 20),
        HashId_1.SHA2_256: (hashlib.sha256, 32),
        HashId_1.SHA2_384: (hashlib.sha384, 48),
        HashId_1.SHA2_512: (hashlib.sha512, 64),
    }
    DIGESTS = {
        PrfId.PRF_HMAC_MD5: (hashlib.md5, 16),
        PrfId.PRF_HMAC_SHA1: (hashlib.sha1, 20),
        PrfId.PRF_HMAC_SHA2_256: (hashlib.sha256, 32),
        PrfId.PRF_HMAC_SHA2_384: (hashlib.sha384, 48),
        PrfId.PRF_HMAC_SHA2_512: (hashlib.sha512, 64),
    }
    def __init__(self, transform):
        self.hasher, self.key_size = self.DIGESTS[transform] if type(transform) is PrfId else self.DIGESTS_1[transform]
    def prf(self, key, data):
        return hmac.HMAC(key, data, digestmod=self.hasher).digest()
    def prfplus(self, key, seed, count=True):
        temp = bytes()
        for i in range(1, 1024):
            temp = self.prf(key, temp + seed + (bytes([i]) if count else b''))
            yield from temp

class Integrity:
    DIGESTS_1 = {
        IntegId_1.AUTH_HMAC_MD5: (hashlib.md5, 16, 12),
        IntegId_1.AUTH_HMAC_SHA1: (hashlib.sha1, 20, 12),
        IntegId_1.AUTH_HMAC_SHA2_256: (hashlib.sha256, 32, 16),
        IntegId_1.AUTH_HMAC_SHA2_384: (hashlib.sha384, 48, 24),
        IntegId_1.AUTH_HMAC_SHA2_512: (hashlib.sha512, 64, 32),
    }
    DIGESTS = {
        IntegId.AUTH_HMAC_MD5_96: (hashlib.md5, 16, 12),
        IntegId.AUTH_HMAC_SHA1_96: (hashlib.sha1, 20, 12),
        IntegId.AUTH_HMAC_MD5_128: (hashlib.md5, 16, 16),
        IntegId.AUTH_HMAC_SHA1_160: (hashlib.sha1, 20, 20),
        IntegId.AUTH_HMAC_SHA2_256_128: (hashlib.sha256, 32, 16),
        IntegId.AUTH_HMAC_SHA2_384_192: (hashlib.sha384, 48, 24),
        IntegId.AUTH_HMAC_SHA2_512_256: (hashlib.sha512, 64, 32),
    }
    def __init__(self, transform):
        self.hasher, self.key_size, self.hash_size = self.DIGESTS[transform] if type(transform) is IntegId else self.DIGESTS_1[transform]
    def compute(self, key, data):
        return hmac.HMAC(key, data, digestmod=self.hasher).digest()[:self.hash_size]

def calculate_checksum(encrypted,sk_a,INTEG_ID):
    #print("Integrity ID = ",INTEG_ID)
    integr = Integrity(INTEG_ID)
    checksum = Integrity.compute(integr, sk_a, encrypted)
    return checksum

def verify_checksum(encrypted, sk_a, integrity_id):
    #print("Integrity ID = ",INTEG_ID)
    integr = Integrity(integrity_id)
    checksum = Integrity.compute(integr,sk_a, encrypted[:len(encrypted)-integr.hash_size])
    return checksum == encrypted[len(encrypted)-integr.hash_size:]

def decrypt(encrypted, sk_e, ecnryption_id, integrity_id):
    encr = Cipher(ecnryption_id, len(sk_e))
    integr = Integrity(integrity_id)
    #print("Integrity Hash Size = ",integr.hash_size)
    iv = encrypted[:encr.block_size]
    ciphertext = encrypted[encr.block_size:len(encrypted)-integr.hash_size]
    plain = encr.cipher.new(sk_e, encr.aes_mode, bytes(iv)).decrypt(bytes(ciphertext))
    padlen = plain[-1]
    return plain[:-1-padlen]

def encrypt(plaintext, sk_e, ecnryption_id, integrity_id):
    print(f"encrypt {plaintext}")
    integr = Integrity(integrity_id)
    if ecnryption_id == EncrId.ENCR_NULL:
        return plaintext + b'\x00' * integr.hash_size
    encr = Cipher(ecnryption_id, len(sk_e))
    iv = generate_iv(encr.block_size)
    padlen = encr.block_size - (len(plaintext) % encr.block_size) - 1
    plaintext += b'\x00' * padlen + bytes([padlen])
    print(f"encrypt2 {plaintext}")
    ciphertext= encr.cipher.new(sk_e, encr.aes_mode, bytes(iv)).encrypt(plaintext)
    encrypted = iv + ciphertext
    encrypted = encrypted + b'\x00' * integr.hash_size
    return encrypted

def create_key(PRF_id, INTEG_id, ENCR_id, ENCR_keylen, shared_secret, my_nonce, peer_nonce, my_spi, peer_spi, old_sk_d=None):
    prf = Prf(PRF_id)
    integ = Integrity(INTEG_id)
    cipher = Cipher(ENCR_id,ENCR_keylen)
    if not old_sk_d:
        skeyseed = prf.prf(my_nonce + peer_nonce, shared_secret)
    else:
        skeyseed = prf.prf(old_sk_d, shared_secret + my_nonce + peer_nonce)
    keymat_fmt = struct.Struct('>{0}s{1}s{1}s{2}s{2}s{0}s{0}s'.format(prf.key_size, integ.key_size, cipher.key_size))
    keymat = prf.prfplus(skeyseed, my_nonce + peer_nonce + my_spi + peer_spi)
    sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr = keymat_fmt.unpack(bytes(next(keymat) for _ in range(keymat_fmt.size)))
    return sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr

def dh_generate_key(group):
    if group not in DH_GROUPS:
        raise NotImplementedError(f'Unsupported DH Group DH_{group}')
    dh_type, params = DH_GROUPS[group]
    if dh_type == DHType.DH_MODP:
        p, g, dh_key_size = params
        print(p, g, dh_key_size)
        dh_private_key = dh.DHParameterNumbers(p, g).parameters().generate_private_key()
        dh_public_key_bytes = dh_private_key.public_key().public_numbers().y.to_bytes(dh_key_size, 'big')
    elif dh_type == DHType.DH_ECDH:
        dh_private_key = ec.generate_private_key(params)
        dh_key_size = (dh_private_key.key_size + 7) // 8
        dh_public_numbers = dh_private_key.public_key().public_numbers()
        dh_public_key_bytes = dh_public_numbers.x.to_bytes(dh_key_size, 'big') + dh_public_numbers.y.to_bytes(dh_key_size, 'big')
    elif dh_type == DHType.DH_X25519:
        dh_private_key = params.X25519PrivateKey.generate()
        dh_public_key_bytes = dh_private_key.public_key().public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw)
        dh_key_size = len(dh_public_key_bytes)
    else:
        raise NotImplementedError()
    return dh_private_key, dh_public_key_bytes, dh_key_size

def dh_calculate_shared_key(group, peer_public_key_bytes, dh_key_size, dh_private_key):
    if group not in DH_GROUPS:
        raise NotImplementedError(f'Unsupported DH Group DH_{group}')
    dh_type, params = DH_GROUPS[group]
    if dh_type == DHType.DH_MODP:  
        p, g, dh_key_size = params
        peer_public_numbers = dh.DHPublicNumbers(int.from_bytes(peer_public_key_bytes, byteorder='big'), dh.DHParameterNumbers(p, g))
        peer_public_key = peer_public_numbers.public_key()
        dh_shared_key = dh_private_key.exchange(peer_public_key)
        print('DIFFIE-HELLMAN KEY', dh_shared_key)
    elif dh_type == DHType.DH_ECDH:
        peer_public_numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(peer_public_key_bytes[:dh_key_size], 'big'), int.from_bytes(peer_public_key_bytes[dh_key_size:], 'big'), params)
        peer_public_key = peer_public_numbers.public_key()
        dh_shared_key = dh_private_key.exchange(ec.ECDH(), peer_public_key)
    elif dh_type == DHType.DH_X25519:
        peer_public_key = params.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        dh_shared_key = dh_private_key.exchange(peer_public_key)
    else:
        raise NotImplementedError()
    return dh_shared_key
 
