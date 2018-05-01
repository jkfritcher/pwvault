#include <algorithm>
#include <iomanip>
#include <iostream>
#include <fstream>

#include <cstdint>
#include <cstdlib>
#include <strings.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <cryptopp/twofish.h>

using CryptoPP::HMAC;
using CryptoPP::SHA256;
using CryptoPP::Twofish;
using CryptoPP::HexEncoder;

typedef uint8_t byte;

const uint8_t TAG_V3[] = { 'P', 'W', 'S', '3' };
const uint8_t EOF_V3[] = { 'P', 'W', 'S', '3', '-', 'E', 'O', 'F',
                           'P', 'W', 'S', '3', '-', 'E', 'O', 'F' };

void Stretch_Key(uint8_t *, size_t, uint8_t *, size_t, uint32_t, uint8_t *);

int main(int argc, char *argv[])
{
    std::fstream fs(argv[1], std::fstream::in | std::fstream::binary);
    if (fs) {
        char buf[32];
        std::string output;
        HexEncoder encoder(new CryptoPP::StringSink(output));

        /* Check tag */
        fs.read(buf, sizeof(TAG_V3));
        if (memcmp(buf, TAG_V3, sizeof(TAG_V3)) != 0) {
            std::cerr << "Tag does not match!" << std::endl;
            exit(-1);
        }

        /* Check for truncation of file */
        int64_t pos = fs.tellg();
        fs.seekg(-(sizeof(EOF_V3)+SHA256::DIGESTSIZE), std::ios_base::end);
        fs.read(buf, sizeof(EOF_V3));
        if (memcmp(buf, EOF_V3, sizeof(EOF_V3)) != 0) {
            std::cerr << "File appears to be truncated and not properly terminated" << std::endl;
            exit(-1);
        }
        fs.seekg(pos);

        /* Derive master key */
        uint8_t h_p[SHA256::DIGESTSIZE];
        uint8_t salt[32];
        uint32_t iters;
        fs.read((char *)salt, sizeof(salt));
        fs.read((char *)&iters, sizeof(iters));
        fs.read((char *)h_p, sizeof(h_p));
        uint8_t outKey[SHA256::DIGESTSIZE];

        Stretch_Key(salt, sizeof(salt), (uint8_t *)(argv[2]), strlen(argv[2]),
                    iters, outKey);

        /* Check master key verifier */
        if (!SHA256().VerifyDigest(h_p, outKey, SHA256::DIGESTSIZE)) {
            std::cerr << "Password is not correct!" << std::endl;
            exit(-1);
        }

        encoder.Put(outKey, sizeof(outKey));
        encoder.MessageEnd();
        std::cout << " Master Key: " << output << std::endl;
        output.clear();

        /* Decrypt K and L */
        CryptoPP::SecByteBlock K(32), L(32);
        CryptoPP::ECB_Mode<Twofish>::Decryption d1;
        d1.SetKey(outKey, sizeof(outKey));

        fs.read(buf, sizeof(buf));   /* B1|B2 */
        d1.ProcessData(K, (byte *)buf, sizeof(buf));

        encoder.Put((byte *)buf, sizeof(buf));
        encoder.MessageEnd();
        std::cout << "Encrypted K: " << output << std::endl;
        output.clear();
        encoder.Put(K, K.size());
        encoder.MessageEnd();
        std::cout << "Decrypted K: " << output << std::endl;
        output.clear();

        fs.read(buf, sizeof(buf));   /* B3|B4 */
        d1.ProcessData(L, (byte *)buf, sizeof(buf));

        encoder.Put((byte *)buf, sizeof(buf));
        encoder.MessageEnd();
        std::cout << "Encrypted L: " << output << std::endl;
        output.clear();
        encoder.Put(L, L.size());
        encoder.MessageEnd();
        std::cout << "Decrypted L: " << output << std::endl;
        output.clear();

        CryptoPP::SecByteBlock IV(Twofish::BLOCKSIZE);
        fs.read((char *)IV.BytePtr(), IV.size());
        encoder.Put(IV, IV.size());
        encoder.MessageEnd();
        std::cout << "IV: " << output << std::endl;
        output.clear();

        /* Setup decryptor and HMAC */
        CryptoPP::HMAC<SHA256> hmac(L, L.size());
        CryptoPP::CBC_Mode<Twofish>::Decryption d2;
        d2.SetKeyWithIV(K, K.size(), IV, IV.size());

        std::cout << std::endl << "Headers:" << std::endl;
        const int32_t BLOCKSIZE = Twofish::BLOCKSIZE;
        bool eof = false, headers = true;
        while(!eof) {
            uint8_t buf2[32], plain[256];
            uint32_t fieldLen = 0, i = 0, j = 0;
            uint8_t fieldType = 0;

            bool first_block = true;
            do {
                fs.read((char *)buf2, BLOCKSIZE);
                if (memcmp(buf2, EOF_V3, sizeof(EOF_V3)) == 0) {
                    std::cout << "EOF reached" << std::endl;
                    eof = true;
                    break;
                }

                d2.ProcessData(&plain[j], buf2, BLOCKSIZE);
                if (first_block) {
                    fieldLen = i = *(uint32_t *)plain;
                    fieldType = plain[4];
                    i -= std::min((int)i, BLOCKSIZE-5);
                    first_block = false;
                } else {
                    i -= std::min((int)i, BLOCKSIZE);
                }
                j += BLOCKSIZE;
            } while(i > 0);

            if (fieldLen > 0) {
                hmac.Update(&plain[5], fieldLen);
            }

            if (eof) {
                std::cout << std::endl;

                fs.read((char *)buf2, sizeof(buf2));
                hmac.Final(plain);

                encoder.Put(buf2, sizeof(buf2));
                encoder.MessageEnd();
                std::cout << "  Stored HMAC: " << output << std::endl;
                output.clear();

                encoder.Put(plain, 32);
                encoder.MessageEnd();
                std::cout << "Computed HMAC: " << output << std::endl;
                output.clear();

                if (CryptoPP::VerifyBufsEqual(buf2, plain, sizeof(buf2))) {
                    std::cout << "Data validated successfully!" << std::endl;
                } else {
                    std::cout << "Data failed validation!" << std::endl;
                }

                break;
            }

            if (fieldLen > 0) {
                encoder.Put(&plain[5], fieldLen);
                encoder.MessageEnd();
            }

            std::cout << std::setfill(' ') << std::setw(4) << std::right << std::setbase(10) << fieldLen << " " << std::setbase(16) << std::setw(2) << std::setfill('0') << (int)fieldType << " " << output << std::endl;
            output.clear();

            if (fieldType == 0xff) {
                std::cout << std::endl;
                if (headers) {
                    headers = false;
                    std::cout << "Fields:" << std::endl;
                }
            }
        }
        fs.close();
    }

    return 0;
}

void Stretch_Key(uint8_t *salt, size_t saltLen,
                 uint8_t *passkey, size_t passkeyLen,
                 uint32_t iters, uint8_t *outKey)
{
    uint8_t digest[SHA256::DIGESTSIZE];
    SHA256 H;

    H.Update(passkey, passkeyLen);
    H.Update(salt, saltLen);
    H.Final(digest);

    for(uint32_t i = 0; i < iters; i++) {
        H.Update(digest, SHA256::DIGESTSIZE);
        H.Final(digest);
    }

    memcpy(outKey, digest, sizeof(digest));
}
