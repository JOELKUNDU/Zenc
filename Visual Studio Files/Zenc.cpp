#define _CRT_SECURE_NO_WARNINGS

//HEADERS USED
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <vector>
#include <random>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/sha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
//NAMESPACES
using namespace std;
namespace fs = std::filesystem;
using namespace CryptoPP;

//STRUCTURES
struct config {
    string fpath = "";
    string kpathPass = "";
    string mode = "";
    bool password = false;
    bool keyfile = false;
    bool genpass = false;
    bool enctitle = false;
    bool dectitle = false;
    void parseinput(int argc, char** argv) {
        //Chech the command structure and populate the config struct        
        fpath = argv[2]; //The File to be encrypted
        if (argv[3] != "-m") { //Incorrect input format
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
        else {
            mode = argv[4];//En/Decryption mode
        }
        if (argv[5] == "-p") {//If password or keyfile is mentioned
            kpathPass = argv[6];//Password or path to a previous keyfile
            fs::path p(kpathPass);//check if it's a path to a keyfile
            if (fs::is_regular_file(p) && p.extension().string()==".zkey") {//check if it is a keyfile
                password = false;
                keyfile = true;
            }
            else {//it is a password
                password = true;
                keyfile = false;
            }            
            if (argc > 7) {//checks for additional options
                for (int i = 7; i <= argc; i++) {
                    if (argv[1] == "-e" || argv[1] == "-ed") {
                        if (argv[i] == "-t") {//Encrypt Titles
                            enctitle = true;
                        }
                        else if (argv[i] == "-g") {//Generate a random password
                            genpass = true;
                        }
                        else {//error in input
                            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                            cout << "Press ENTER to continue";
                            getchar();
                            cout.clear();
                            exit(0);
                        }
                    }
                    else if (argv[1] == "-d" || argv[1] == "-dd" && argv[i] == "-t") {//decryption tools don't generate keys
                        dectitle = true;//decrypt the filenames
                    }                        
                    else {//error in input
                        cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                        cout << "Press ENTER to continue";
                        getchar();
                        cout.clear();
                        exit(0);
                    }
                }
            }
        }
        else if ((argv[5] == "-np" || argv[1]=="-e")|| (argv[5] == "-np" || argv[1] == "-ed")) {//incase of decryption this will fail
            password = false;//no password was choosen so a new keyfile will be genrated 
            keyfile = false;
            if (argc > 6) {
                for (int i = 6; i <= argc; i++) {//check for additional options
                    if (argv[1] == "-e" || argv[1] == "-ed") {
                        if (argv[i] == "-t") {// encrypt with encrypted titles
                            enctitle = true;
                        }
                        else if (argv[i] == "-g") {// generate a password
                            genpass = true;
                        }
                        else {//error in input
                            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                            cout << "Press ENTER to continue";
                            getchar();
                            cout.clear();
                            exit(0);
                        }
                    }
                    else if (argv[1] == "-d" || argv[1] == "-dd" && argv[i] == "-t") {// decrypt title
                        dectitle = true;//decrypt the filenames
                    }                        
                    else {//error in input
                        cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                        cout << "Press ENTER to continue";
                        getchar();
                        cout.clear();
                        exit(0);
                    }
                }
            }
        }
        else {//error in input
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
    }    
};

//MISC FUNCTIONS
void help() {
    cout << "::: Zenc HELPBOOK :::" << endl;
    cout << "Zenc <options>\n";
    cout << endl;
    cout << "OPTIONS:\n\n";
    cout << "$ FOR HELP \n";
    cout << "- h or -H\t\t OPEN HELPBOOK\n ";
    cout << endl;
    cout << "$$$$ FOR ENCRYPTING $$$";
    cout << endl;
    cout << "\n$ TO ENCRYPT A FILE" << endl;
    cout << "-e <filepath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-e\t\tTo encrypt a file." << endl;
    cout << "<filepath>\tPath to the file to be encrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tIf you want to enter the <password> or the <path> to an existing .key file" << endl;
    cout << "-np\t\tIf you don;t want to specify a password then a new .key file will be genrated in the same directory";
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tEncrypts the name of the Files also" << endl;
    cout << "-g\t\tGenerates a random password for the file" << endl;

    cout << endl;
    cout << "\n$ TO ENCRYPT A DIR" << endl;
    cout << "-ed <folderpath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-ed\t\tTo encrypt a dir." << endl;
    cout << "<folderpath>\tPath to the file to be encrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tIf you want to enter the <password> or the <path> to an existing .key file" << endl;
    cout << "-np\t\tIf you don;t want to specify a password then a new .key file will be genrated in the same directory";
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tEncrypts the name of the Files also" << endl;
    cout << "-g\t\tGenerates a random password for the file" << endl;

    cout << endl;
    cout << "$$$$ FOR DECRYPTING $$$$" << endl;
    cout << endl;
    cout << "\n$ TO DECRYPT A FILE" << endl;
    cout << "-d <filepath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-d\t\tTo decrypt a file." << endl;
    cout << "<filepath>\tPath to the file to be decrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion used" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tPassword used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption" << endl;
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tMention this if the file names were encrypted" << endl;

    cout << endl;
    cout << "\n$ TO DECRYPT A FOLDER" << endl;
    cout << "-dd <folderpath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-dd\t\tTo decrypt a dir." << endl;
    cout << "<folderpath>\tPath to the file to be decrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion used" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tPassword used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption" << endl;
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tMention this if the file names were encrypted" << endl;
}
string randomgeniv(string password) {
    string out = "";
    string charset = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890*=";
    for (unsigned int i = 0; i < 16; i++) {
        minstd_rand d((int)password.at(i));
        int c = d() % charset.size();
        out += charset.at(c);
    }
    return out;
}
string eraseSubStr(string mainstr, string toErase) {
    size_t pos = mainstr.find(toErase);
    if (pos != std::string::npos) {
        mainstr.erase(pos, toErase.length());
    }
    return mainstr;
}
string getKeypath(string path) {
    int size = path.size()-1,extLen;
    for (unsigned int j = size; j >= 0; j--) {
        if (path.at(j) == '.') {
            extLen = size - j;
            break;
        }
    }
    return path.substr(0, path.size() - extLen) + ".zkey";
}
string genEncTitle(string path) {
    string encpath = "";
    return encpath;
}
string genDecTitle(string path) {
    string encpath = "";
    return encpath;
}

//FUNCTIONS
bool encryptfile(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    if (c.mode == "gcm2k") {
        GCM<AES, GCM_2K_Tables>::Encryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else {
            try {
                //generate the keys
                AutoSeededRandomPool prng;
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                prng.GenerateBlock(key, sizeof(key));
                CryptoPP::byte iv[AES::BLOCKSIZE];
                prng.GenerateBlock(iv, sizeof(iv));
                string kpath = getKeypath(c.fpath);
                fstream writek(kpath, ios::out | ios::binary);
                writek.write((char*)key, sizeof(key));
                writek.write((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR making keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        //encrypt the files
        string encpath;
        try {
            if (c.enctitle) {
                //genrate encrypted title
                encpath = genEncTitle(c.fpath);
            }
            else {
                encpath = c.fpath + ".Zenc";
            }
            FileSource f(c.fpath.c_str(), true, new AuthenticatedEncryptionFilter(e, new FileSink(encpath.c_str())));
        }
        catch (...) {
            cerr << "ERROR encrypting file (mode: " + c.mode + ")";
            exit(EXIT_FAILURE);
        }
        return true;        
    }
    else if (c.mode == "gcm64k") {
        GCM<AES, GCM_64K_Tables>::Encryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else {
            try {
                //generate the keys
                AutoSeededRandomPool prng;
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                prng.GenerateBlock(key, sizeof(key));
                CryptoPP::byte iv[AES::BLOCKSIZE];
                prng.GenerateBlock(iv, sizeof(iv));
                string kpath = getKeypath(c.fpath);
                fstream writek(kpath, ios::out | ios::binary);
                writek.write((char*)key, sizeof(key));
                writek.write((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR making keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        //encrypt the files
        string encpath;
        try {
            if (c.enctitle) {
                //genrate encrypted title
                encpath = genEncTitle(c.fpath);
            }
            else {
                encpath = c.fpath + ".Zenc";
            }
            FileSource f(c.fpath.c_str(), true, new AuthenticatedEncryptionFilter(e, new FileSink(encpath.c_str())));
        }
        catch (...) {
            cerr << "ERROR encrypting file (mode: " + c.mode + ")";
            exit(EXIT_FAILURE);
        }
        return true;
    }

    return false;
}
bool encryptfolder(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    if (c.mode == "gcm2k") {
        GCM<AES, GCM_2K_Tables>::Encryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else {
            try {
                //generate the keys
                AutoSeededRandomPool prng;
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                prng.GenerateBlock(key, sizeof(key));
                CryptoPP::byte iv[AES::BLOCKSIZE];
                prng.GenerateBlock(iv, sizeof(iv));
                string kpath = getKeypath(c.fpath);
                fstream writek(kpath, ios::out | ios::binary);
                writek.write((char*)key, sizeof(key));
                writek.write((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR making keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        //encrypt the files
        string encpath;
        fs::path enciter(c.fpath);
        for (auto& file : fs::recursive_directory_iterator(enciter)) {
            try {
                string filepath = file.path().string();
                if (c.enctitle) {
                    //genrate encrypted title
                    encpath = genEncTitle(filepath);
                }
                else {
                    encpath = file.path().string() + ".Zenc";
                }
                FileSource f(filepath.c_str(), true, new AuthenticatedEncryptionFilter(e, new FileSink(encpath.c_str())));
            }
            catch (...) {
                cerr << "ERROR encrypting file (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        return true;
    }
    else if (c.mode == "gcm64k") {
        GCM<AES, GCM_64K_Tables>::Encryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else {
            try {
                //generate the keys
                AutoSeededRandomPool prng;
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                prng.GenerateBlock(key, sizeof(key));
                CryptoPP::byte iv[AES::BLOCKSIZE];
                prng.GenerateBlock(iv, sizeof(iv));
                string kpath = getKeypath(c.fpath);
                fstream writek(kpath, ios::out | ios::binary);
                writek.write((char*)key, sizeof(key));
                writek.write((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR making keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        //encrypt the files
        string encpath;
        fs::path enciter(c.fpath);
        for (auto& file : fs::recursive_directory_iterator(enciter)) {
            try {
                string filepath = file.path().string();
                if (c.enctitle) {
                    //genrate encrypted title
                    encpath = genEncTitle(filepath);
                }
                else {
                    encpath = file.path().string() + ".Zenc";
                }
                FileSource f(filepath.c_str(), true, new AuthenticatedEncryptionFilter(e, new FileSink(encpath.c_str())));
            }
            catch (...) {
                cerr << "ERROR encrypting file (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }       
        return true;
    }

    return false;
}
bool decryptfile(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    if (c.mode == "gcm2k") {
        GCM<AES, GCM_2K_Tables>::Decryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }

        //encrypt the files
        string encpath;
        try {
            if (c.enctitle) {
                //genrate decrypted title
                encpath = genDecTitle(c.fpath);
            }
            else {
                encpath = eraseSubStr(c.fpath, ".Zenc");
            }
            FileSource f(c.fpath.c_str(), true, new AuthenticatedDecryptionFilter(e, new FileSink(encpath.c_str())));
        }
        catch (...) {
            cerr << "ERROR encrypting file (mode: " + c.mode + ")";
            exit(EXIT_FAILURE);
        }
        return true;
    }
    else if (c.mode == "gcm64k") {
        GCM<AES, GCM_64K_Tables>::Encryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        //encrypt the files
        string encpath;
        try {
            if (c.enctitle) {
                //genrate decrypted title
                encpath = genDecTitle(c.fpath);
            }
            else {
                encpath = eraseSubStr(c.fpath,".Zenc");
            }
            FileSource f(c.fpath.c_str(), true, new AuthenticatedDecryptionFilter(e, new FileSink(encpath.c_str())));
        }
        catch (...) {
            cerr << "ERROR encrypting file (mode: " + c.mode + ")";
            exit(EXIT_FAILURE);
        }
        return true;
    }
    return false;
}
bool decryptfolder(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    if (c.mode == "gcm2k") {
        GCM<AES, GCM_2K_Tables>::Decryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        //encrypt the files
        string encpath;
        fs::path enciter(c.fpath);
        for (auto& file : fs::recursive_directory_iterator(enciter)) {
            try {
                string filepath = file.path().string();
                if (c.enctitle) {
                    //genrate Decrypted title
                    encpath = genDecTitle(filepath);
                }
                else {
                    encpath = eraseSubStr(c.fpath, ".Zenc");
                }
                FileSource f(filepath.c_str(), true, new AuthenticatedDecryptionFilter(e, new FileSink(encpath.c_str())));
            }
            catch (...) {
                cerr << "ERROR decrypting file (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        return true;
    }
    else if (c.mode == "gcm64k") {
        GCM<AES, GCM_64K_Tables>::Decryption e;
        //setup password
        if (c.password) {
            try {
                string password = c.kpathPass;
                string iv = randomgeniv(password);
                //hdkf
                SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
                HKDF<SHA256> hkdf;
                hkdf.DeriveKey(key, key.size(), (const unsigned char*)password.data(), password.size(),
                    (const unsigned char*)iv.data(), iv.size(), NULL, 0);
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            catch (...) {
                cerr << "ERROR deriving key from password (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        else if (c.keyfile) {
            try {
                string pathKey = c.kpathPass;
                fstream readk(pathKey, ios::in | ios::binary);
                CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
                CryptoPP::byte iv[AES::BLOCKSIZE];
                readk.read((char*)key, sizeof(key));
                readk.read((char*)iv, sizeof(iv));
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            catch (...) {
                cerr << "ERROR reading keyfile (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }

        //encrypt the files
        string encpath;
        fs::path enciter(c.fpath);
        for (auto& file : fs::recursive_directory_iterator(enciter)) {
            try {
                string filepath = file.path().string();
                if (c.enctitle) {
                    //genrate decrypted title
                    encpath = genDecTitle(filepath);
                }
                else {
                    encpath = eraseSubStr(c.fpath, ".Zenc");
                }
                FileSource f(filepath.c_str(), true, new AuthenticatedDecryptionFilter(e, new FileSink(encpath.c_str())));
            }
            catch (...) {
                cerr << "ERROR encrypting file (mode: " + c.mode + ")";
                exit(EXIT_FAILURE);
            }
        }
        return true;
    }
    return true;
}

//MAIN FUNCTION
int main(int argc, char** argv)
{
    //Check the option being used ie -h/-H or -e or -ed or -d or -dd
    string option = argv[1];
    //if option was for help
    if (option == "-h" || option == "-H") {
        help();
        return 0;
    }
    //if -e
    else if (option == "-e") {
        if (!encryptfile(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
    }
    //if -ed
    else if (option == "-ed") {
        if (!encryptfolder(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
    }
    //if -d
    else if (option == "-d") {
        if (!decryptfile(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
    }
    //if -dd
    else if (option == "-dd") {
        if (!decryptfolder(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
    }
    //wrong input
    else {
        cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
        cout << "Press ENTER to continue";
        getchar();
        cout.clear();
        exit(0);
    }
}

