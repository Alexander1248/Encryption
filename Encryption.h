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

void RSAKeyGen(unsigned int openKey[2], unsigned int secretKey[2], int len , int maxlen) {
	srand(clock());

	//Finding the pseudo-simple n1 and n2
	const int PNum[54] = { 2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251 };
	bool f = false;
	unsigned int n1, n2;
	while (f != true) {
		n1 = 2 + rand() % (maxlen - 1);
		for (int i = 0; i < 54; i++) if (n1 % PNum[i] != 0) f = true;
		if (f == true) {
			f = false;
			int k = 0;
			for (int rounds = 1; rounds < trunc(log2(n1)); rounds++) {
				if (n1 % (2 + rand() % (maxlen - 1)) == 0) k++;
			}
			if (k >= trunc(log2(n1))) f = true;
		}
	}
	f = false;
	while (f != true) {
		n2 = 2 + rand() % (maxlen - 1);
		for (int i = 0; i < 54; i++) if (n2 % PNum[i] != 0) f = true;
		if (f == true) {
			f = false;
			int k = 0;
			for (int rounds = 1; rounds < trunc(log2(n1)); rounds++) {
				if (n1 % (2 + rand() % (maxlen - 1)) == 0) k++;
			}
			if (k >= trunc(log2(n1))) f = true;
		}
	}
	unsigned int n = n1 * n2;
	while (n < len || n > maxlen) {
		while (f != true) {
			n1 = 1 + rand() % maxlen;
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
		while (f != true) {
			n2 = 1 + rand() % maxlen;
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
		unsigned int n = n1 * n2;
	}
	//Calculating the RSA key of the encryption algorithm
	unsigned int nEyler = (n1 - 1) * (n2 - 1);
	unsigned int e = 1 + rand() % nEyler;
	double dr = (1 % nEyler) / e;
	while (greatest_common_divisor(e, nEyler) != 1 and dr == trunc(dr)) e = 1 + rand() % nEyler, dr = (1 % nEyler) / e;
	unsigned int d = dr;
	openKey[0] = e;
	secretKey[0] = d;
	openKey[1] = secretKey[1] = n;
}

void RSAEncryption(unsigned int& encrypted,unsigned int openKey[2],int message,bool error) {
	if (message >= openKey[1]) error = true;
	else {
		encrypted = 1;
		for (int i = 0; i < openKey[0]; i++) {
			encrypted = message * encrypted % openKey[1];
		}
	}
}

void RSADecryption(unsigned int& decrypted, unsigned int secretKey[2], int message, bool error) {
	if (message >= secretKey[1]) error = true;
	else {
		decrypted = 1;
		for (int i = 0; i < secretKey[0]; i++) {
			decrypted = message * decrypted % secretKey[1];
		}
	}
}


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

//A simple encryptor based on the Vigener cipher
void VijenerEncryptor(char data[],char key[],int len,bool keyGen) {
	if (keyGen == true) {
		srand(int(data) + len);
		for (int i = 0; i < len; i++) key[i] = 33 + rand() % 223;
	}
	// Shift encoder
	for (int i = 0; i < len; i++) {
		data[i] += key[i];
		while (data[i] > 255) data[i] -= 223;
	}
}

//A simple decoder with the Vigenère cipher
void  VijenerDecryptor(char data[], char key[], int len) {
	//Reverse shift decoder
	for (int i = 0; i < len; i++) {
		data[i] -= key[i];
		while (data[i] < 33) data[i] += 233;
	}
}

void SHP_2(char*& hashed, char* data, int dataLen, int hashLen) {
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

bool Xor(bool x, bool y) {
	if (x == false && y == false) return false;
	if (x == true && y == false) return true;
	if (x == false && y == true) return true;
	if (x == true && y == true) return false;
}

void int_to_binary(bool*& binary, int data,int& len) {
	int c = data; int k = 0;
	while (c != 0) {
		c = trunc((float)c / 2);
		k++;
	}
	len = k;
	binary = new bool[k];
	c = data;
	while (k > 0) {
		binary[k - 1] = c % 2;
		c = trunc((float)c / 2);
		k--;
	}
}

void binary_to_int(bool* binary, int& data ,int len) {
	data = 0;
	for (int i = 0; i < len; i++) {
		data += binary[i] * pow(2, len - i - 1);
	}
}

int lib(int itemN , int libN) {
	const int data0[256] = { 0, 258, 523, 739, 967, 369, 647, 691, 9, 236, 394, 980, 87, 511, 794, 872,
91, 328, 630, 927, 193, 299, 743, 951, 275, 359, 802, 943, 338, 374, 894, 46,
183, 472, 750, 6, 162, 490, 660, 91, 383, 647, 726, 906, 316, 716, 840, 153,
281, 575, 769, 28, 380, 634, 934, 960, 199, 565, 732, 966, 379, 395, 734, 273,
383, 667, 911, 103, 375, 621, 843, 191, 531, 616, 17, 52, 390, 905, 994, 222,
495, 751, 994, 254, 531, 853, 980, 399, 651, 659, 872, 453, 463, 965, 825, 67,
561, 861, 135, 316, 679, 951, 24, 450, 632, 831, 962, 330, 667, 56, 979, 671,
680, 929, 138, 377, 656, 47, 99, 467, 808, 996, 57, 672, 575, 800, 33, 351,
771, 21, 263, 595, 734, 990, 372, 687, 926, 159, 430, 745, 45, 173, 144, 522,
849, 108, 355, 569, 903, 153, 456, 546, 769, 11, 399, 852, 746, 250, 687, 940,
948, 188, 506, 724, 63, 200, 504, 750, 91, 110, 601, 722, 127, 308, 728, 969,
49, 300, 594, 839, 1, 426, 516, 722, 2, 506, 447, 948, 276, 354, 476, 980,
137, 377, 682, 877, 202, 409, 624, 919, 261, 364, 748, 777, 24, 408, 801, 246,
261, 506, 770, 79, 217, 616, 735, 937, 253, 710, 644, 230, 488, 757, 43, 853,
350, 629, 825, 163, 359, 689, 972, 49, 376, 519, 790, 982, 495, 673, 917, 59,
453, 714, 905, 265, 388, 805, 1, 126, 345, 585, 840, 250, 719, 606, 146, 89 };
	const int data1[256] = { 172, 716, 577, 811, 706, 773, 940, 617, 449, 697, 511, 230, 3, 657, 87, 659,
270, 293, 844, 222, 91, 532, 877, 455, 603, 436, 296, 873, 921, 721, 485, 241,
385, 512, 21, 809, 608, 202, 880, 776, 488, 913, 377, 385, 476, 595, 544, 378,
320, 957, 684, 788, 717, 901, 951, 690, 602, 977, 859, 517, 59, 30, 106, 408,
519, 477, 126, 387, 542, 520, 6, 638, 708, 395, 699, 624, 722, 622, 491, 354,
245, 555, 861, 841, 538, 611, 972, 211, 888, 414, 872, 524, 3, 941, 515, 75,
710, 685, 460, 254, 962, 746, 145, 83, 868, 924, 712, 330, 92, 91, 144, 938,
890, 419, 762, 510, 898, 900, 417, 714, 834, 74, 669, 770, 694, 969, 735, 764,
758, 815, 525, 86, 641, 287, 747, 48, 44, 949, 595, 988, 634, 356, 876, 334,
623, 602, 249, 802, 579, 525, 479, 26, 887, 587, 636, 380, 19, 150, 470, 636,
380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380,
19, 150, 470, 636, 380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380, 19,
150, 470, 636, 380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380, 19, 150,
470, 636, 380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380, 19, 150, 470,
636, 380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380, 19, 150, 470, 636,
380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380, 19, 150, 470, 636, 380 };
	const int data2[256] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719,
727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827,
829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619 };
	if (libN == 0) return data0[itemN % 256];
	if (libN == 1) return data1[itemN % 256];
	if (libN == 2) return data2[itemN % 256];

	if (libN > 2) return -1;
}

void libEncryptor(char data[], char key[], int len, bool keyGen) {
	if (keyGen == true) {
		srand(int(data) + len);
		for (int i = 0; i < len; i++) key[i] = 33 + rand() % 223;
	}

	for (int i = 0; i < len; i++) {
		data[i] += key[i];
		data[i] -= lib(key[i], 0);
		data[i] += lib(key[len - 1 - i], 1);
		data[i] -= lib(key[len - 1 - i], 2);
		while (data[i] > 255) data[i] -= 223;
		while (data[i] < 33) data[i] += 233;
	}
}

void libDecryptor(char data[], char key[], int len) {
	for (int i = 0; i < len; i++) {
		data[i] -= key[i];
		data[i] += lib(key[i], 0);
		data[i] -= lib(key[len - 1 - i], 1);
		data[i] += lib(key[len - 1 - i], 2);
		while (data[i] > 255) data[i] -= 223;
		while (data[i] < 33) data[i] += 233;
	}
}


void ShiftEncryptor(char data[], char*& key, int len, bool keyGen) {
	if (keyGen == true) {
		key = new char[len];
		srand(int(data) + len);
		for (int i = 0; i < len; i++) key[i] = 33 + rand() % 223;
	}

	for (int i = 0; i < len; i++) {
		data[i] += key[i];
		while (data[i] > 255) data[i] -= 223;
	}

	for (int i = 0; i < len; i++) {
		char b = data[i];
		data[i] = data[lib(key[i], 1) % len];
		data[lib(key[i], 1) % len] = b;
	}

	for (int i = len - 1; i >= 0; i--) {
		char b = data[i];
		data[i] = data[lib(key[i], 2) % len];
		data[lib(key[i], 2) % len] = b;
	}
}

void  ShiftDecryptor(char data[], char key[], int len) {
	
	for (int i = 0; i < len; i++) {
		char b = data[i];
		data[i] = data[lib(key[i], 2) % len];
		data[lib(key[i], 2) % len] = b;
	}

	for (int i = len - 1; i >= 0; i--) {
		char b = data[i];
		data[i] = data[lib(key[i], 1) % len];
		data[lib(key[i], 1) % len] = b;
	}

	for (int i = 0; i < len; i++) {
		data[i] -= key[i];
		while (data[i] < 33) data[i] += 233;
	}
}


//A simple encryptor based on the Cesar cipher
void CesarEncryptor(char data[], int& key, int len, bool keyGen) {
	if (keyGen == true) {
		srand(int(data) + len);
		key = rand() % 1000;
	}
	// Shift encoder
	for (int i = 0; i < len; i++) {
		data[i] += key;
		while (data[i] > 255) data[i] -= 223;
	}
}

//A simple decoder with the Cesar cipher
void  CesarDecryptor(char data[], char key, int len) {
	//Reverse shift decoder
	for (int i = 0; i < len; i++) {
		data[i] -= key;
		while (data[i] < 33) data[i] += 233;
	}
}
