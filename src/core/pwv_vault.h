
#ifndef PWV_CORE_VAULT_H
#define PWV_CORE_VAULT_H

#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>

#include <string>
#include <vector>

namespace pwv {

// Holds sensitive data and will eventually be stored in wired memory
typedef struct VaultSecMem {
    VaultSecMem() : k(32), l(32), p(CryptoPP::SHA256::DIGESTSIZE), t(16) { }
    CryptoPP::SecByteBlock k;
    CryptoPP::SecByteBlock l;
    CryptoPP::SecByteBlock p;
    CryptoPP::SecByteBlock t;
} VaultSecMem_t;

class Vault
{
    public:
        static Vault* NewVault(std::string& password, size_t iters=16384);

    private:
        std::vector<uint8_t> salt_;
        std::vector<uint8_t> h_p_;
        VaultSecMem_t *sec_mem_;
        size_t iters_;

        Vault();
        ~Vault();

        bool Initialize(std::string &password, size_t iters);
        bool Load(std::string& filename, std::string& password);
};
}

#endif /* PWV_CORE_VAULT_H */
