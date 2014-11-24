#define VERIFY
#define NO_STATIC_KEYS

#include <iostream>
#include <sstream>
#include <cstdio>
#include <ctime>

#include <stdexcept>

using std::string;
using std::stringstream;
using std::cout;
using std::endl;
using std::cerr;
using std::runtime_error;
using std::time;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "integer.h"
using CryptoPP::Integer;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;

#include "filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;

#include "dh.h"
using CryptoPP::DH;

#include "dh2.h"
using CryptoPP::DH2;

#include "oids.h"
using CryptoPP::OID;

#include "eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;
using CryptoPP::ECMQV;

// ASN1 is a namespace, not an object
#include "asn.h"
using namespace CryptoPP::ASN1;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "aes.h"
using CryptoPP::AES;

#include "salsa.h"
using CryptoPP::Salsa20;

#include "sosemanuk.h"
using CryptoPP::Sosemanuk;

#include "sha.h"
using CryptoPP::SHA256;

#include "hmac.h"
using CryptoPP::HMAC;

#include "cmac.h"
using CryptoPP::CMAC;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;


//~Function Typedefs-------------------------------------------------------------------
typedef void (*SecretGenerator)(SecByteBlock &secret);
typedef void (*SymmetricKeyGenerator)(SecByteBlock &secret, 
										byte *iv[], 
										int *ivLength,
										SecByteBlock &key);
typedef void (*SymmetricCipher)(string &plaintext, 
								string &ciphertext,
								byte *iv, 
								SecByteBlock &key);
typedef void (*SymmetricDecipher)(string &plaintext, 
									string &ciphertext,
									byte *iv, 
									SecByteBlock &key);
typedef void (*MACCompute)(string &plain, 
							string &mac, 
							SecByteBlock &key);
typedef void (*MACVerify)(string &plain, 
							string &mac, 
							SecByteBlock &key);

//~Variables & Constants-------------------------------------------------------------------------
#define SECRET_LENGTH 256

//Pre-shared keys
const static Integer secret1("0xA988184F4F70F4FEA499C91A603DF69DEE4C9DB8F688B1F09AE27F36522795"
		"1DDD9B96E79A7DBC9D68C950557A7B91E2B571F759EAFA57906F6442C6DA4"
		"6957DF1247C46FB37BCEE8512BDAABDBED6BB520315E6520A79D637869255"
		"FA57F4985956266B95FEC758A96B62A285752008D56949A9034564253AC44"
		"79B297370DB170D59BAAB23793731D1968C47E95A0B59FE4B5FECCADA2DCE"
		"6E2F48BFBAFE00545040469FBF8021BABB1B51A8192966B3354882866A867"
		"571799A1AE936F8DE244AE9B0C1121248FB145189F6495A4A21459D291CDD"
		"5FABC4A33D6B4DEF2A143EF3BF417F96F4638ABE2711713D4C16852A92F65"
		"80148B525397C1E9E8D5E3D");
const static Integer secret2("0x8F3EC7D71B5B441B0F604D63D79916CB5C4BB5CF1737A003793D33E508A849"
		"C5F1A2F9C7AF1E3F14C2C505B69621A50E6340B55D20413B2854EBD523D681D6D"
		"0F4D92C6BD93D7278B5FF28DD015B93C206551FA945F62CBC532209FA468CAE0A"
		"592DDE6A020F5A9ADC68EC5C8F2B563851D75CD8E376EFCF4A9E212D40469AB49"
		"C31E1E761CF9A41DCCE9C730DCA5000BF42E38144104240DB171D1AA13EEBD5A5"
		"CECFC12273834DA38EFBC2A64796A1E61AF7191AD52F872003EB51C4D3534217A"
		"CF32790A90825434A157A8F4348663968E7C836A889DEE803D1AFFDFE7ABA0939"
		"9CFF9B619152D9D4C810234D30BC8A0A827B4662048C1AB7B860841B1F57");
const static Integer secret3("0x33748D4E070CA41C6E102A041465410A9541AE26373FBBAD87965FC62C0B6536B2"
		"2A2E544D7489093B5B533C44C8FC24C97C9C37D1E0FB70EF17A6D1D00382821A5"
		"41F98C594CDBE937121C38A2A806FCE5134537E7C2ABFD244C7CF6407096A936E"
		"456824B29157F04869441119826E40346A06F1B22E1F2755F12FC021566538885"
		"C1C7CC25FFFA330EBBB16E532574C149B70C947DFB3EE9051A21771EF0ED2D953"
		"D7B3600548780F5C42A11FC04C59DA98DB1D22288B77ABDD9EB56008687F81013"
		"AE5EBD60B284FF69A0406F3CA0BAB8A7071632D0A6160C4E0910B19A7FAA33B15"
		"40E10357457232CC08796F826AF8ECAC61832FF4AE4C44262C31DAD8");
const static Integer secret4("0x671722C9E76DD81A1C906E3F8C1251FCCFDB26E800BE6CBD2611EE6A26DFFF3D50"
		"F01EF84FBD887BDBB674F76132615D4FFC9EA7E49221F0CD81C40255866FF442B"
		"FF524F4CE4DC2133904DAD3618CF45027D4A0C2A64EE12F27079185E7122AC48A"
		"98930B09D32EC9D076C6FF3292972F328F7D85C2577658A3172E48A0CF9F6CA50"
		"3479680CD6A9351F76F06DB736AF25CC683840EB606A37BE71731E3C10B95B2D8"
		"731B9420711249363F996DC1DC07F9E4634A7352C46DFF5F1099917783D185281"
		"E6DB6584F8CF0041D248B98984E741B5CEFCCDF10571AD3C406DDF1DB1A06FCBE"
		"16EBFE37B9CDB31E9110043087960E1D3D8A5BFB8AB05196919AEF33");

//~Convenience Functions------------------------------------------------
void PrintSecByteBlock(SecByteBlock &block) {

	string encoded;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource ss1(block, 
						block.size(), 
						true, 
						new HexEncoder(new StringSink(encoded)));

	cout << "Passed Block: " << encoded << endl;
}

//TODO: REMOVE HALF THE COMPUTATIONS
//~Protocols code-------------------------------------------------------------------
//~Secret Generators=================================================================
void GetSecret1(SecByteBlock &secret) {

	byte secret1Bytes[SECRET_LENGTH];
	secret1.Encode(secret1Bytes, SECRET_LENGTH);
	secret.Assign(secret1Bytes, SECRET_LENGTH);
}

void GetSecret2(SecByteBlock &secret) {

	byte secret2Bytes[SECRET_LENGTH];
	secret2.Encode(secret2Bytes, SECRET_LENGTH);
	secret.Assign(secret2Bytes, SECRET_LENGTH);
}

void GetSecret3(SecByteBlock &secret) {

	byte secret3Bytes[SECRET_LENGTH];
	secret3.Encode(secret3Bytes, SECRET_LENGTH);
	secret.Assign(secret3Bytes, SECRET_LENGTH);
}

void GetSecret4(SecByteBlock &secret) {

	byte secret4Bytes[SECRET_LENGTH];
	secret4.Encode(secret4Bytes, SECRET_LENGTH);
	secret.Assign(secret4Bytes, SECRET_LENGTH);
}

//This EphemeralDH code taken from the cryptopp wiki page
void EphemeralDH(SecByteBlock &secret) {

	//Use pre-shared prime and generator-------------------------------	
	// RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
	// http://tools.ietf.org/html/rfc5114#section-2.1
	const static Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
		"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
		"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
		"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
		"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
		"DF1FB2BC2E4A4371");

	const static Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
		"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
		"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
		"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
		"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
		"855E6EEB22B3B2E5");

	const static Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");		
	// Schnorr Group primes are of the form p = rq + 1, p and q prime. They
	// provide a subgroup order. In the case of 1024-bit MODP Group, the
	// security level is 80 bits (based on the 160-bit prime order subgroup).		

	// For a compare/contrast of using the maximum security level, see
	// dh-unified.zip. Also see http://www.cryptopp.com/wiki/Diffie-Hellman
	// and http://www.cryptopp.com/wiki/Security_level .

	//////////////////////////////////////////////////////////////////////////
	// Alice

	// Initialize the Diffie-Hellman class with a pre-selected prime & base
	DH dhA;
	AutoSeededRandomPool rndA;
	dhA.AccessGroupParameters().Initialize(p, q, g);

	//Setup DH2 (ephemeral (authentication))
	DH2 dh2A(dhA);

	SecByteBlock sprivA(dh2A.StaticPrivateKeyLength()), spubA(dh2A.StaticPublicKeyLength());
	SecByteBlock eprivA(dh2A.EphemeralPrivateKeyLength()), epubA(dh2A.EphemeralPublicKeyLength());

	dh2A.GenerateStaticKeyPair(rndA, sprivA, spubA);
	dh2A.GenerateEphemeralKeyPair(rndA, eprivA, epubA);

	//////////////////////////////////////////////////////////////////////////
	// Bob
	// Initialize the Diffie-Hellman class with the pre-selected prime and base provided
	DH dhB;
	AutoSeededRandomPool rndB;
	dhB.AccessGroupParameters().Initialize(p, q, g);

	//Setup DH2 (ephemeral (authentication))
	DH2 dh2B(dhB);

	SecByteBlock sprivB(dh2B.StaticPrivateKeyLength()), spubB(dh2B.StaticPublicKeyLength());
	SecByteBlock eprivB(dh2B.EphemeralPrivateKeyLength()), epubB(dh2B.EphemeralPublicKeyLength());

	dh2B.GenerateStaticKeyPair(rndB, sprivB, spubB);		
	dh2B.GenerateEphemeralKeyPair(rndB, eprivB, epubB);

	//////////////////////////////////////////////////////////////////////////
	// Agreement
	if(dh2A.AgreedValueLength() != dh2B.AgreedValueLength())
		throw runtime_error("Shared secret size mismatch");

	SecByteBlock sharedA(dh2A.AgreedValueLength());
	SecByteBlock sharedB(dh2B.AgreedValueLength());

	if(!dh2A.Agree(sharedA, sprivA, eprivA, spubB, epubB))
		throw runtime_error("Failed to reach shared secret (A)");

	if(!dh2B.Agree(sharedB, sprivB, eprivB, spubA, epubA))
		throw runtime_error("Failed to reach shared secret (B)");

	//Copy shared key into passed in SecByteBlock
	secret.Assign(sharedA);
}

//This ECDH code taken from the cryptopp wiki page
void ECDHAgreement(SecByteBlock &secret) {

	OID CURVE = secp256r1();
    AutoSeededRandomPool prng;

    ECDH <ECP>::Domain dhA(CURVE), dhB(CURVE);

    SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());

    dhA.GenerateKeyPair(prng, privA, pubA);
    dhB.GenerateKeyPair(prng, privB, pubB);

    if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
		throw runtime_error("Shared secret size mismatch");

    SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());

    const bool rtn1 = dhA.Agree(sharedA, privA, pubB);
    const bool rtn2 = dhB.Agree(sharedB, privB, pubA);
    if(!rtn1 || !rtn2)
		throw runtime_error("Failed to reach shared secret (A)");

    const bool rtn3 = sharedA.size() == sharedB.size();
    if(!rtn3)
		throw runtime_error("Failed to reach shared secret (B)");

    Integer a, b;

    a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    //cout << "(A): " << std::hex << a << endl;
    b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    //cout << "(B): " << std::hex << b << endl;

    const bool rtn4 = a == b;
    if(!rtn4)
		throw runtime_error("Failed to reach shared secret (C)");

    //cout << "Agreed to shared secret" << endl;

    secret.Assign(sharedA);
}

//This ECMQVA code taken from the cryptopp wiki page
void ECMQVAgreement(SecByteBlock &secret) {

	OID CURVE = secp256r1();
	AutoSeededRandomPool rng;

	ECMQV <ECP>::Domain mqvA(CURVE), mqvB(CURVE);

	// Party A, static (long term) key pair
	SecByteBlock sprivA(mqvA.StaticPrivateKeyLength()), spubA(mqvA.StaticPublicKeyLength());
	// Party A, ephemeral (temporary) key pair
	SecByteBlock eprivA(mqvA.EphemeralPrivateKeyLength()), epubA(mqvA.EphemeralPublicKeyLength());

	// Party B, static (long term) key pair
	SecByteBlock sprivB(mqvB.StaticPrivateKeyLength()), spubB(mqvB.StaticPublicKeyLength());
	// Party B, ephemeral (temporary) key pair
	SecByteBlock eprivB(mqvB.EphemeralPrivateKeyLength()), epubB(mqvB.EphemeralPublicKeyLength());

	// Imitate a long term (static) key
	mqvA.GenerateStaticKeyPair(rng, sprivA, spubA);
	// Ephemeral (temporary) key
	mqvA.GenerateEphemeralKeyPair(rng, eprivA, epubA);

	// Imitate a long term (static) key
	mqvB.GenerateStaticKeyPair(rng, sprivB, spubB);
	// Ephemeral (temporary) key
	mqvB.GenerateEphemeralKeyPair(rng, eprivB, epubB);

	if(mqvA.AgreedValueLength() != mqvB.AgreedValueLength())
	    throw runtime_error("Shared secret size mismatch");

	SecByteBlock sharedA(mqvA.AgreedValueLength()), sharedB(mqvB.AgreedValueLength());

	if(!mqvA.Agree(sharedA, sprivA, eprivA, spubB, epubB))
	    throw runtime_error("Failed to reach shared secret (A)");

	if(!mqvB.Agree(sharedB, sprivB, eprivB, spubA, epubA))
	    throw runtime_error("Failed to reach shared secret (B)");

	Integer ssa, ssb;

	ssa.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
	//cout << "(A): " << std::hex << ssa << endl;

	ssb.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
	//cout << "(B): " << std::hex << ssb << endl;

	if(ssa != ssb)
	    throw runtime_error("Failed to reach shared secret (C)");

	//cout << "Agreed to shared secret" << endl;

	secret.Assign(sharedA);
}

//~SYMMETRIC KEY GENERATORS===========================================================================
//This AES code adapted with the help of the cryptopp wiki page
void AESKeyGeneration(SecByteBlock &secret, 
						byte *iv[],
						int *ivLength,
						SecByteBlock &key) {

	AutoSeededRandomPool prng;

	//AES KEYGEN--------------------------------------------------------------
	// Calculate a SHA-256 hash over the secret
	key.CleanNew(SHA256::DIGESTSIZE);
	SHA256().CalculateDigest(key, secret, secret.size()); 

	// Generate a random IV
	*ivLength = AES::BLOCKSIZE;
	*iv = new byte[*ivLength];
	prng.GenerateBlock(*iv, *ivLength);
}

void Salsa20KeyGeneration(SecByteBlock &secret,
							byte *iv[],
							int *ivLength,
							SecByteBlock &key) {

	AutoSeededRandomPool prng;

	key.CleanNew(SHA256::DIGESTSIZE);
	SHA256().CalculateDigest(key, secret, secret.size());

	*ivLength = 64;
	*iv = new byte[*ivLength];
	prng.GenerateBlock(*iv, *ivLength);	
}


//From the Sosemanuk Paper
/*
Sosemanuk is a new synchronous software-oriented stream cipher, corresponding to
Profile 1 of the ECRYPT call for stream cipher primitives. Its key length is variable
between 128 and 256 bits. It accommodates a 128-bit initial value. Any key length is
claimed to achieve 128-bit security. The Sosemanuk cipher uses both some basic design
principles from the stream cipher SNOW 2.0 and some transformations derived from
the block cipher SERPENT. Sosemanuk aims at improving SNOW 2.0 both from the
security and from the efficiency points of view. Most notably, it uses a faster IV-setup
procedure. It also requires a reduced amount of static data, yielding better performance
on several architectures.
*/
void SosemanukKeyGeneration(SecByteBlock &secret,
							byte *iv[],
							int *ivLength,
							SecByteBlock &key) {

	AutoSeededRandomPool prng;

	key.CleanNew(SHA256::DIGESTSIZE);
	SHA256().CalculateDigest(key, secret, secret.size());

	*ivLength = 64;
	*iv = new byte[*ivLength];
	prng.GenerateBlock(*iv, *ivLength);	
}

//~SYMMETRIC CRYPTO======================================================================================
//This AES code adapted with the help of the cryptopp wiki page
void AESEncrypt(string &plaintext,
					string &ciphertext,
					byte *iv,
					SecByteBlock &key) {

	ciphertext = "";
	//////////////////////////////////////////////////////////////////////////
	// Encrypt
	CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss(plaintext, true, 
        new StreamTransformationFilter(e, new StringSink(ciphertext)));
}
//This AES code adapted with the help of the cryptopp wiki page
void AESDecrypt(string &ciphertext,
					string &plaintext,
					byte *iv,
					SecByteBlock &key) {
	
	plaintext = "";
	CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource ss(ciphertext, true, 
        new StreamTransformationFilter(d, new StringSink(plaintext))); 
}

void Salsa20Encrypt(string &plaintext,
					string &ciphertext,
					byte *iv,
					SecByteBlock &key) {

	byte *plaintextBytes = (byte *) plaintext.c_str();
	byte *ciphertextBytes = new byte[plaintext.length()];

	Salsa20::Encryption salsa;
	salsa.SetKeyWithIV(key.BytePtr(), key.size(), iv);
	salsa.ProcessData(ciphertextBytes, plaintextBytes, plaintext.length());
	ciphertext.assign((char *) ciphertextBytes);

	delete ciphertextBytes;
}

void Salsa20Decrypt(string &ciphertext,
					string &plaintext,
					byte *iv,
					SecByteBlock &key) {

	return Salsa20Encrypt(ciphertext, plaintext, iv, key);
}

void SosemanukEncrypt(string &plaintext,
						string &ciphertext,
						byte *iv,
						SecByteBlock &key) {

	byte *plaintextBytes = (byte *) plaintext.c_str();
	byte *ciphertextBytes = new byte[plaintext.length()];

	Sosemanuk::Encryption sos;	
	sos.SetKeyWithIV(key.BytePtr(), key.size(), iv);
	sos.ProcessData(ciphertextBytes, plaintextBytes, plaintext.length());
	ciphertext.assign((char *) ciphertextBytes);

	delete ciphertextBytes;
}

void SosemanukDecrypt(string &ciphertext,
						string &plaintext,
						byte *iv,
						SecByteBlock &key) {

	return SosemanukEncrypt(ciphertext, plaintext, iv, key);
}

//~MACS==========================================================================================
//This HMAC code obtained from the cryptopp wiki page
void HMACCompute(string &plaintext, string &mac, SecByteBlock &key) {

	mac = "";
	try
	{
		HMAC<SHA256> hmac(key, key.size());		

		StringSource(plaintext, 
						true, 
						new HashFilter(hmac, new StringSink(mac)));
	}
	catch(const CryptoPP::Exception& e)
	{
		cout << "PROBLEM IN HMACCompute!!!" << endl;
		cerr << e.what() << endl;
		exit(1);
	}
}

//This HMAC code obtained from the cryptopp wiki page
void HMACVerify(string &plaintext, string &mac, SecByteBlock &key) {

	try
	{
		HMAC<SHA256> hmac(key, key.size());
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

		// Tamper with message
		// plain[0] ^= 0x01;

		// Tamper with MAC
		// mac[0] ^= 0x01;
	
		StringSource(plaintext + mac, true, 
			new HashVerificationFilter(hmac, NULL, flags)
		); // StringSource

		cout << "Verified message" << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cout << "PROBLEM IN HMACVerify!!!" << endl;
		cerr << e.what() << endl;
		exit(1);
	}
}

//This CMAC code obtained from the cryptopp wiki page
void CMACCompute(string &plaintext, string &mac, SecByteBlock &key) {

	try
	{
	    CMAC<AES> cmac(key, key.size());

	    StringSource(plaintext, 
	    				true, 
	        			new HashFilter(cmac, new StringSink(mac)));
	}
	catch(const CryptoPP::Exception& e)
	{
	    cerr << e.what() << endl;
	    cout << "Error in CMACCompute." << endl;
	}
}

//This CMAC code obtained from the cryptopp wiki page
void CMACVerify(string &plaintext, string &mac, SecByteBlock &key) {

	try
	{
	    CMAC<AES> cmac(key.data(), key.size());

	    StringSource((plaintext + mac), 
	    				true, 
	        			new HashVerificationFilter(cmac, new StringSink(mac)));

	    cout << "Verified CMAC message" << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
	    cerr << e.what() << endl;
	    cout << "Error in CMACVerify." << endl;
	    cout << "Failed to verify!!!" << endl;
	}
}

//~TimeStamp=====================================================================
void TimeStamp(string &timestamp) {

	time_t curTime;
	time(&curTime);
	stringstream ss;
	ss << curTime;
	timestamp = ss.str();
}

//~Message Constructions=========================================================

//Driver code------------------------------------------------------------
void Simulation(string &message, 
				string &messageCiphertext,
				SecretGenerator secretGenerator,
				SymmetricKeyGenerator symmetricKeyGenerator,
				SymmetricCipher symmetricCipher,
				SymmetricDecipher symmetricDecipher,
				MACCompute macCompute,
				MACVerify macVerify) {

	string mac("");
	SecByteBlock secret(0);
	SecByteBlock key(0);
	byte *iv = NULL;
	int ivLength = 0;

	//secretGenerator
	secretGenerator(secret);

	//symmetricKeyGenerator
	//Generate symmetric key and iv
	symmetricKeyGenerator(secret, &iv, &ivLength, key);

	//symmetricCipher
	symmetricCipher(message, messageCiphertext, iv, key);
#ifdef VERIFY
	cout << "plaintext: ||" << message << "||" << endl;
	cout << "ciphertext: " << messageCiphertext << endl;
	symmetricDecipher(messageCiphertext, message, iv, key);
	cout << "plaintext again: ||" << message << "||" << endl;
#endif

	//messageAuthentication
	macCompute(messageCiphertext, mac, key);
#ifdef VERIFY
	macVerify(messageCiphertext, mac, key);
#endif

	delete iv;
}

//~Main runner-----------------------------------------------------------------------
#define NUM_SECRET_GENS 7
//TODO: Reg DH, ECDH, EC Menezes-Qu-Vanstone, Fully Hashed Menezes-Qu-Vanstone
const static string secretGeneratorNames[] = {"Ephemeral Diffie-Hellman", 
												"Elliptic Curve Diffie-Hellman",
												"Elliptic Curve Menezes-Qu-Vanstone",
												"Static Key 1", 
												"Static Key 2", 
												"Static Key 3", 
												"Static Key 4"};
const static SecretGenerator secretGenerators[] = {EphemeralDH, 
													ECDHAgreement,
													ECMQVAgreement,
													GetSecret1, 
													GetSecret2, 
													GetSecret3, 
													GetSecret4};

#define NUM_SYMMETRICS 3
//TODO: (high speed STREAM ciphers) Salsa20, Sosemanuk
//TODO: 3DES, IDEA, Blowfish
const static string symmetricCipherNames[] = {"AES", "Salsa20", "Sosemanuk"};
const static SymmetricKeyGenerator symmetricKeyGenerators[] = {AESKeyGeneration, 
																Salsa20KeyGeneration,
																SosemanukKeyGeneration};
const static SymmetricCipher symmetricCiphers[] = {AESEncrypt, 
													Salsa20Encrypt, 
													SosemanukEncrypt};
const static SymmetricCipher symmetricDeciphers[] = {AESDecrypt, 
														Salsa20Decrypt, 
														SosemanukDecrypt};

#define NUM_MACS 2
//TODO: VMAC, CBC-MAC, DMAC, Two-Track-MAC
const static string macNames[] = {"HMAC", "CMAC"};
const static MACCompute macComputers[] = {HMACCompute,
											CMACCompute};
const static MACCompute macVerifiers[] = {HMACVerify,
											CMACVerify};

//TODO: Look into Block cipher modes
//TODO: Look into Stream cipher modes

#define NUM_TRIALS 1

int main() {

	cout << endl;

	time_t startTime, endTime, diffTime, trials[NUM_TRIALS];
	double avgTime = 0;

	string message("HI I ENCRYPT STUFF!");
	string messageCiphertext("");
	//TODO: Add different messages

	int numSecretGens = NUM_SECRET_GENS;
#ifdef NO_STATIC_KEYS
	numSecretGens -= 4;
#endif
	for (int i = 0; i < numSecretGens; i++) {

		for (int j = 0; j < NUM_SYMMETRICS; j++) {

			for (int k = 0; k < NUM_MACS; k++) {

				cout << "Secret Generator: " << secretGeneratorNames[i] << endl
						<< "Symmetric Cipher: " << symmetricCipherNames[j] << endl
						<< "MAC: " << macNames[k] << endl << endl;

				for (int t = 0; t < NUM_TRIALS; t++) {

					time(&startTime);
					
					Simulation(message, 
								messageCiphertext,
								secretGenerators[i],
								symmetricKeyGenerators[j],
								symmetricCiphers[j],
								symmetricDeciphers[j],
								macComputers[k],
								macVerifiers[k]);

					time(&endTime);
					diffTime = endTime - startTime;
					trials[t] = diffTime;
				}

				avgTime = 0;
				for (int m = 0; m < NUM_TRIALS; m++) {
					avgTime += trials[m];
				}
				cout << "Calced Average Time: " 
						<< (avgTime / NUM_TRIALS) << endl 
						<< endl << endl;;
			}
		}
	}

	return 0;
}
