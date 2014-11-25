#include <iostream>

using std::string;
using std::stringstream;
using std::cout;
using std::endl;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "aes.h"
using CryptoPP::AES;

#include "vmac.h"
using CryptoPP::VMAC;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;

#include "iterhash.h"
using CryptoPP::IteratedHashBase;

#include "secblock.h"
using CryptoPP::SecByteBlock;

int main() {

	string ciphertext("");
	string plaintext("Why hello there, I'm plaintext, what might you be?");
	byte digestBytes[16];
	byte digestBytes2[16];
	AutoSeededRandomPool prng;

	SecByteBlock key(AES::BLOCKSIZE);
	SecByteBlock iv(AES::BLOCKSIZE);

	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	VMAC<AES> vmac;
	cout << vmac.StaticAlgorithmName() << endl;
	cout << "DIgest Size: " << vmac.DigestSize() << endl;

	//VMAC Computation
	vmac.SetKeyWithIV(key, key.size(), iv.BytePtr());
    vmac.CalculateDigest(digestBytes, (byte *) plaintext.c_str(), plaintext.length());

    //VMAC Verification
    vmac.SetKeyWithIV(key, key.size(), iv.BytePtr());
    vmac.CalculateDigest(digestBytes2, (byte *) plaintext.c_str(), plaintext.length());

    for (int i = 0; i < 16; i++) {

    	if (digestBytes[i] != digestBytes2[i]) {

    		cout << "VMAC VERIFICATION FAILED!" << endl;
    		exit(1);
    	}
    }

    cout << "VMAC VERIFIED!" << endl;

	return 0;
}