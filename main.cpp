#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <filesystem>
#include <random>
#include <thread>
#include <vector>
#include <chrono>
#include <ctime>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "nlohmann/json.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

#ifdef _WIN32
void setColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
#else
void setColor(int) {}
#endif

void log(const std::string& msg) {
    std::ofstream logFile("toolkit.log", std::ios::app);
    if (!logFile) return;

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    logFile << "[" << std::put_time(std::localtime(&now), "%F %T") << "] " << msg << "\n";
}

void loadPlugin(const std::string& path) {
#ifdef _WIN32
    HMODULE lib = LoadLibraryA(path.c_str());
    if (!lib) {
        std::cerr << "Failed to load plugin.\n";
        return;
    }
    typedef void (*PluginFunc)();
    PluginFunc run = (PluginFunc)GetProcAddress(lib, "run");
    if (run) run();
    else std::cerr << "Function 'run' not found in plugin\n";
    FreeLibrary(lib);
#else
    void* lib = dlopen(path.c_str(), RTLD_LAZY);
    if (!lib) {
        std::cerr << "Failed to load plugin: " << dlerror() << "\n";
        return;
    }
    typedef void (*PluginFunc)();
    PluginFunc run = (PluginFunc)dlsym(lib, "run");
    if (run) run();
    else std::cerr << "Function 'run' not found in plugin\n";
    dlclose(lib);
#endif
}

#ifdef _WIN32
bool injectDLL(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    void* alloc = VirtualAllocEx(hProc, nullptr, dllPath.size(), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, alloc, dllPath.c_str(), dllPath.size(), nullptr);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        alloc, 0, nullptr);

    if (hThread) {
        CloseHandle(hThread);
        CloseHandle(hProc);
        return true;
    }
    return false;
}
#endif

void showBanner() {
    setColor(11);
    std::cout << R"(
Command Line Toolkit C++
)";
    setColor(7);
}

void help() {
    setColor(14);
    std::cout << "Commands:\n";
    std::cout << "  help                            Show help\n";
    std::cout << "  encrypt/decrypt <in> <out> <key>  XOR file\n";
    std::cout << "  aes_encrypt/aes_decrypt <in> <out> <key>\n";
    std::cout << "  hash <file>                     SHA-256 hash\n";
    std::cout << "  listdir <path>                  List directory\n";
    std::cout << "  scan_multi <path1> <path2> ...  Threaded scan\n";
    std::cout << "  compare <f1> <f2>               Compare files\n";
    std::cout << "  generate_key <length>           Gen key\n";
    std::cout << "  read_config <file>              Read JSON config\n";
    std::cout << "  plugin <dll_or_so>              Load plugin\n";
#ifdef _WIN32
    std::cout << "  inject <pid> <dll>              DLL Injection\n";
#endif
    std::cout << "  log_test                        Write test log\n";
    std::cout << "  exit                            Quit\n";
    setColor(7);
}

void xorFile(const std::string& in, const std::string& out, const std::string& key) {
    std::ifstream fin(in, std::ios::binary);
    std::ofstream fout(out, std::ios::binary);
    if (!fin || !fout) {
        std::cerr << "File open failed.\n"; return;
    }

    char ch;
    size_t i = 0, klen = key.length();
    while (fin.get(ch)) {
        fout.put(ch ^ key[i % klen]);
        i++;
    }
    std::cout << "XOR operation complete.\n";
}

bool aesEncrypt(const std::string& inFile, const std::string& outFile, const std::string& keyStr) {
    std::ifstream in(inFile, std::ios::binary);
    std::ofstream out(outFile, std::ios::binary);
    if (!in || !out) return false;

    unsigned char key[32] = {}, iv[16] = {};
    memcpy(key, keyStr.c_str(), std::min((size_t)32, keyStr.size()));
    RAND_bytes(iv, 16);
    out.write((char*)iv, 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    char inBuf[1024], outBuf[1040];
    int outLen;
    while (in.read(inBuf, sizeof(inBuf)) || in.gcount()) {
        EVP_EncryptUpdate(ctx, (unsigned char*)outBuf, &outLen, (unsigned char*)inBuf, in.gcount());
        out.write(outBuf, outLen);
    }
    EVP_EncryptFinal_ex(ctx, (unsigned char*)outBuf, &outLen);
    out.write(outBuf, outLen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aesDecrypt(const std::string& inFile, const std::string& outFile, const std::string& keyStr) {
    std::ifstream in(inFile, std::ios::binary);
    std::ofstream out(outFile, std::ios::binary);
    if (!in || !out) return false;

    unsigned char key[32] = {}, iv[16];
    memcpy(key, keyStr.c_str(), std::min((size_t)32, keyStr.size()));
    in.read((char*)iv, 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    char inBuf[1024], outBuf[1040];
    int outLen;
    while (in.read(inBuf, sizeof(inBuf)) || in.gcount()) {
        EVP_DecryptUpdate(ctx, (unsigned char*)outBuf, &outLen, (unsigned char*)inBuf, in.gcount());
        out.write(outBuf, outLen);
    }
    EVP_DecryptFinal_ex(ctx, (unsigned char*)outBuf, &outLen);
    out.write(outBuf, outLen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void hashFile(const std::string& file) {
    std::ifstream f(file, std::ios::binary);
    if (!f) { std::cerr << "Open failed\n"; return; }

    SHA256_CTX ctx; SHA256_Init(&ctx);
    char buf[8192]; while (f.read(buf, sizeof(buf))) SHA256_Update(&ctx, buf, f.gcount());
    SHA256_Update(&ctx, buf, f.gcount());

    unsigned char hash[SHA256_DIGEST_LENGTH]; SHA256_Final(hash, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    std::cout << "\n";
}

void compareFiles(const std::string& a, const std::string& b) {
    std::ifstream f1(a, std::ios::binary), f2(b, std::ios::binary);
    if (!f1 || !f2) return;

    char c1, c2; size_t pos = 0;
    while (f1.get(c1) && f2.get(c2)) {
        if (c1 != c2) {
            std::cout << "Diff at " << pos << ": " << (int)c1 << " != " << (int)c2 << "\n"; return;
        } ++pos;
    }
    if (f1.get(c1) || f2.get(c2)) std::cout << "Length mismatch\n";
    else std::cout << "Files identical\n";
}

void scanDirectory(const std::string& path) {
    for (const auto& entry : fs::recursive_directory_iterator(path))
        std::cout << entry.path() << "\n";
}

void multiThreadedScan(const std::vector<std::string>& paths) {
    std::vector<std::thread> threads;
    for (auto& p : paths) threads.emplace_back(scanDirectory, p);
    for (auto& t : threads) t.join();
}

void generateKey(int len) {
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd; std::mt19937 rng(rd());
    std::uniform_int_distribution<> dist(0, chars.size() - 1);
    std::string key; for (int i = 0; i < len; ++i) key += chars[dist(rng)];
    std::cout << "Key: " << key << "\n";
}

void readJsonConfig(const std::string& path) {
    std::ifstream f(path);
    if (!f || fs::is_empty(path)) {
        std::cerr << "Error: Cannot read or file is empty: " << path << "\n";
        return;
    }

    try {
        json j;
        f >> j;
        std::cout << std::setw(2) << j << "\n";
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << "\n";
    }
}

int main() {
    showBanner(); help();
    std::string input;
    while (true) {
        std::cout << "\n> ";
        std::getline(std::cin, input);
        std::istringstream iss(input);
        std::string cmd; iss >> cmd;

        if (cmd == "exit") break;
        else if (cmd == "help") help();
        else if (cmd == "encrypt" || cmd == "decrypt") {
            std::string in, out, key; iss >> in >> out >> key;
            xorFile(in, out, key); log("XOR " + in);
        }
        else if (cmd == "aes_encrypt" || cmd == "aes_decrypt") {
            std::string in, out, key; iss >> in >> out >> key;
            bool ok = (cmd == "aes_encrypt") ? aesEncrypt(in, out, key) : aesDecrypt(in, out, key);
            if (!ok) std::cerr << "AES failed\n";
            log(cmd + " " + in);
        }
        else if (cmd == "hash") {
            std::string file; iss >> file; hashFile(file); log("hash " + file);
        }
        else if (cmd == "listdir") {
            std::string path; iss >> path;
            for (const auto& e : fs::directory_iterator(path)) std::cout << e.path().filename() << "\n";
        }
        else if (cmd == "compare") {
            std::string a, b; iss >> a >> b; compareFiles(a, b);
        }
        else if (cmd == "scan_multi") {
            std::vector<std::string> paths; std::string p;
            while (iss >> p) paths.push_back(p);
            multiThreadedScan(paths);
        }
        else if (cmd == "generate_key") {
            int len; iss >> len; generateKey(len);
        }
        else if (cmd == "read_config") {
            std::string path; iss >> path; readJsonConfig(path);
        }
        else if (cmd == "plugin") {
            std::string path; iss >> path; loadPlugin(path);
        }
#ifdef _WIN32
        else if (cmd == "inject") {
            DWORD pid; std::string dll; iss >> pid >> dll;
            if (injectDLL(pid, dll)) std::cout << "DLL injected\n";
            else std::cout << "Injection failed\n";
        }
#endif
        else if (cmd == "log_test") {
            log("Test log entry");
            std::cout << "Logged.\n";
        }
        else std::cout << "Unknown command: " << cmd << "\n";
    }
    return 0;
}