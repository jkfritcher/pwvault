#include "pwv_vault.h"

#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

#include <iostream>
#include <fstream>
#include <string>

using CryptoPP::SHA256;

static const uint8_t TAG_V3[] = { 'P', 'W', 'S', '3' };
static const uint8_t EOF_V3[] = { 'P', 'W', 'S', '3', '-', 'E', 'O', 'F',
                           'P', 'W', 'S', '3', '-', 'E', 'O', 'F' };

static
void Stretch_Key(uint8_t *salt, size_t saltLen,
                 uint8_t *passkey, size_t passkeyLen,
                 uint32_t iters, uint8_t *outKey)
{
    CryptoPP::SecByteBlock digest(SHA256::DIGESTSIZE);
    SHA256 H;

    H.Update(passkey, passkeyLen);
    H.Update(salt, saltLen);
    H.Final(digest);

    for(uint32_t i = 0; i < iters; i++) {
        H.Update(digest, SHA256::DIGESTSIZE);
        H.Final(digest);
    }

    ::memcpy(outKey, digest, digest.size());
}

namespace pwv {

Vault* Vault::NewVault(std::string& password, size_t iters)
{
    Vault *v = new Vault();
    v->Initialize(password, iters);
    return v;
}

bool Vault::Initialize(std::string& password, size_t iters)
{
    if (this->sec_mem_ == nullptr)
        return false;

    // Save iters
    this->iters_ = iters;

    // Generate Salt
    CryptoPP::OS_GenerateRandomBlock(false, this->salt_.data(), this->salt_.size());

    // Calculate P
    Stretch_Key(this->salt_.data(), this->salt_.size(),
                (uint8_t *)password.data(), password.size(),
                this->iters_, this->sec_mem_->p);

    // Generate H(P)
    SHA256().CalculateDigest(this->h_p_.data(), this->sec_mem_->p, SHA256::DIGESTSIZE);

    // Generate K
    CryptoPP::OS_GenerateRandomBlock(false, this->sec_mem_->k, this->sec_mem_->k.size());

    // Generate L
    CryptoPP::OS_GenerateRandomBlock(false, this->sec_mem_->l, this->sec_mem_->l.size());

    return true;
}

bool Vault::Load(std::string& filename, std::string& password)
{
    std::fstream fs(filename, std::fstream::in | std::fstream::binary);
    if (!fs) {
        std::cerr << "Failed to open '" << filename << "'" << std::endl;
        return false;
    }

    /* Check tag */
    fs.read(buf, sizeof(TAG_V3));
    if (::memcmp(buf, TAG_V3, sizeof(TAG_V3)) != 0) {
        std::cerr << "Tag does not match!" << std::endl;
        return false;
    }
}

Vault::Vault() : salt_(32), h_p_(CryptoPP::SHA256::DIGESTSIZE)
{
    this->sec_mem_ = new VaultSecMem_t();
    // Generate temp key to encrypt records in memory
    CryptoPP::OS_GenerateRandomBlock(false, this->sec_mem_->t, this->sec_mem_->t.size());
}

Vault::~Vault()
{
    if (this->sec_mem_ != nullptr) {
        delete this->sec_mem_;
        this->sec_mem_ = nullptr;
    }
}

} // namespace pwv

int main(int args, char *argv[])
{
    std::string pw("b1l2a3h");
    pwv::Vault *v = pwv::Vault::NewVault(pw);

    return 0;
}