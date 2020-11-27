#include <math.h>
#include <ctime>
#include <string>

void SHP_1(char*& hashed, char* data, int dataLen, int hashLen, int cost) {
	hashed = new char[hashLen];
	int k = 0;
	//Creating a hash data structure
	for (int i = 0; i < hashLen; i++) {
		hashed[i] = data[k];
		k++;
		if (k >= dataLen) k = 0;
	}
	// Exchange of values to form a primary structure
	for (int i = 0; i < hashLen; i++) {
		char b = hashed[hashLen - 1];
		hashed[hashLen - 1] = hashed[hashed[i] % hashLen];
		hashed[hashed[i] % hashLen] = b;
	}
	long sum = 0;
	//Wave editing of the hash (this is where the effect of rebuilding the hash due to a single character appears)
	if (hashLen >= dataLen) {
		// Wave editing with a shorter length of incoming data compared to the length of the hash itself
		for (int epoch = 0; epoch < cost; epoch++) {
			for (int j = 0; j < hashLen; j++) {
				for (int i = 0; i < j; i++) {
					sum += hashed[i];
				}
				for (int i = j + 1; i < hashLen; i++) {
					sum -= hashed[i];
				}
				hashed[j] = 33 + abs(sum) % 57;
			}
		}
	}
	else {
		// Wave editing when the input data is longer than the hash itself
		for (int epoch = 0; epoch < cost; epoch++) {
			for (int j = 0; j < hashLen; j++) {
				for (int i = 0; i < j; i++) {
					sum += hashed[i];
					//Payment of excess data
					for (int d = i; d < j; d++) {
						sum += data[d];
					}
					for (int d = j + 1; d < dataLen; d++) {
						sum -= data[d];
					}
				}
				for (int i = j + 1; i < hashLen; i++) {
					sum -= hashed[i];
					//Payment of excess data
					for (int d = i; d < j + 1; d++) {
						sum += data[d];
					}
					for (int d = j + 2; d < dataLen; d++) {
						sum -= data[d];
					}
				}
				hashed[j] = 33 + abs(sum) % 57;
			}
		}
	}
}

unsigned int greatest_common_divisor(unsigned int a, unsigned int b) {
	if (a % b == 0)
		return b;
	if (b % a == 0)
		return a;
	if (a > b)
		return greatest_common_divisor(a % b, b);
	return greatest_common_divisor(a, b % a);
}

void RSAKeyGen(unsigned int openKey[2], unsigned int secretKey[2]) {
	srand(clock());

	const int PNum[54] = { 2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251 };
	bool f = false;
	unsigned int n1, n2;
	//Finding the pseudo-simple n1
	while (f != true) {
		n1 = 1000 + rand() % 64535;
		for (int i = 0; i < 54; i++) if (n1 % PNum[i] != 0) f = true;
		if (f == true) {
			f = false;
			int k = 0;
			for (int rounds = 1; rounds < trunc(log2(n1)); rounds++) {
				if (n1 % (2 + rand() % 65532) == 0) k++;
			}
			if (k >= trunc(log2(n1))) f = true;
		}
	}
	f = false;
	//Finding the pseudo-simple n2
	while (f != true) {
		n2 = 1000 + rand() % 64535;
		for (int i = 0; i < 54; i++) if (n2 % PNum[i] != 0) f = true;
		if (f == true) {
			f = false;
			int k = 0;
			for (int rounds = 1; rounds < trunc(log2(n1)); rounds++) {
				if (n1 % (2 + rand() % 65532) == 0) k++;
			}
			if (k >= trunc(log2(n1))) f = true;
		}
	}
	//Calculating the RSA key of the encryption algorithm
	unsigned int n = n1 * n2;
	unsigned int nEyler = (n1 - 1) * (n2 - 1);
	unsigned int e = 1000 + rand() % (nEyler - 1000);
	double dr = (1 % nEyler) / e;
	while (greatest_common_divisor(e, nEyler) != 1 and dr == trunc(dr)) e = 1000 + rand() % (nEyler - 1000), dr = (1 % nEyler) / e;
	unsigned int d = dr;
	openKey[0] = e;
	secretKey[0] = d;
	openKey[1] = secretKey[1] = n;
}

//Work In Progress...
void RSAEncryption(unsigned int encrypted,unsigned int openKey[2],int message,bool error) {
	if (message >= openKey[1]) error = true;
	else {
		encrypted = pow(message, openKey[0]);
		encrypted = encrypted % openKey[1];
	}
}
void RSADecryption(unsigned int decrypted, unsigned int secretKey[2], int message, bool error) {
	if (message >= secretKey[1]) error = true;
	else {
		decrypted = pow(message, secretKey[0]);
		decrypted = decrypted % secretKey[1];
	}
}
//...

//Transformer values of the first generation
void HPMv1(char* data, int dataLen) {
	for (int i = 0; i < dataLen; i++) {
		int j = data[i] % dataLen;
		char b = data[i];
		data[i] = data[j];
		data[j] = b;
	}
}

//Transformer values of the second generation
void HPMv2(char* data, int dataLen) {
	for (int j = 1; j <= dataLen; j++) {
		for (int i = j; i < dataLen; i += j) {
			char b = data[i];
			data[i] = data[i - j];
			data[i - j] = b;
		}
	}
}

//Transformer values of the third generation
void HPMv3(char* data, int dataLen) {
	char* hash;
	for (int i = 0; i < dataLen; i++) {
		SHP_1(hash, data, dataLen, dataLen, 10);
		int j = int(hash[i]) % dataLen;
		char b = data[i];
		data[i] = data[j];
		data[j] = b;
	}
}

//A simple encryptor based on the Vigener cipher
void SEPEncryption(char data[],char key[],int len,bool keyGen) {
	//Генерация ключа(если keyGen == true)
	if (keyGen == true) {
		srand(int(data) + len);
		for (int i = 0; i < len; i++) key[i] = 33 + rand() % 223;
	}
	// Shift encoder
	for (int i = 0; i < len; i++) {
		data[i] += key[i];
		if (data[i] > 255) data[i] -= 223;
	}
}

//A simple decoder with the Vigenère cipher
void SEPDecryption(char data[], char key[], int len) {
	//Reverse shift decoder
	for (int i = 0; i < len; i++) {
		data[i] -= key[i];
		if (data[i] < 33) data[i] += 233;
	}
}


void SHP_2(char*& hashed, char* data,int dataLen, int hashLen) {
	//Primary processing
	HPMv2(data, dataLen);

	//Primary hashing with subsequent processing
	char* hash = new char[64];
	SHP_1(hash, data, dataLen, 64, 10);
	HPMv1(hash, 64);

	//Repeated hashing with two-step processing
	char* hash1 = new char[256];
	SHP_1(hash1, hash, 64, 256, 10);
	HPMv1(hash1, 256);
	HPMv2(hash1, 256);

	//Final hashing with processing
	SHP_1(hashed, hash1, 256, hashLen, 10);
	HPMv2(hashed, hashLen);
}

void SHP_3(char*& hashed, char* data, int dataLen, int hashLen) {
	//Primary processing
	HPMv3(data, dataLen);

	//Weak hashing followed by two-step processing
	//(not an improved hashing method due to the low speed of the improved method compared to the classic one)
	char* hash = new char[64];
	SHP_1(hash, data, dataLen, 64, 10);
	HPMv1(hash, 64);
	HPMv3(hash, 256);

	//Re-hashing with an improved algorithm with three-step processing
	char* hash1 = new char[256];
	SHP_2(hash1, hash, 64, 256);
	HPMv1(hash1, 256);
	HPMv2(hash1, 256);
	HPMv3(hash1, 256);

	//Final hashing with an improved algorithm with two-step processing
	SHP_2(hashed, hash1, 256, hashLen);
	HPMv3(hashed, hashLen);
	HPMv2(hash1, 256);
}

//Work In Progress...
void SlideEncryptor(char* data, int dataLen) {
	for (int j = 0; j < dataLen; j++) {
		for (int i = 0; i < dataLen - j; i++) {
			char b = data[j];
			data[j] = data[i];
			data[i] = b;
		}
	}
}
void SlideDecryptor(char* data, int dataLen) {
	for (int j = 0; j < dataLen; j++) {
		for (int i = dataLen - j - 1; i > 0; i--) {
			char b = data[j];
			data[j] = data[i];
			data[i] = b;
		}
	}
}
//...