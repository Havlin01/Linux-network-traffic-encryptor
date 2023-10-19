#include <iostream>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>

using namespace CryptoPP;

void GenerateECDHKeys()
{
    AutoSeededRandomPool prng;

    // Vyberte 512-bitovou k�ivku
    ECDH <ECP>::Domain dh;
    dh.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());

    // Generov�n� priv�tn�ho kl��e
    DH_PrivateKey<ECP> privateKey;
    privateKey.Initialize(prng, dh);

    // Extrahov�n� ve�ejn�ho kl��e
    DH_PublicKey<ECP> publicKey;
    privateKey.MakePublicKey(publicKey);

    // V�stup ve�ejn�ho a soukrom�ho kl��e
    std::cout << "Ve�ejn� kl��: " << std::hex << publicKey.GetPublicElement() << std::dec << std::endl;
    std::cout << "Soukrom� kl��: " << std::hex << privateKey.GetPrivateExponent() << std::dec << std::endl;
}

int main()
{
  
    // Generov�n� kl���
    GenerateECDHKeys();

    return 0;
}
