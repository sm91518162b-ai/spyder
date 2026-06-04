// spyder.cpp — Spyder 4.0.2 | Built by 5 AIs 🕷️
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>
#include <chrono>
#include <array>
#include <set>
#include <unordered_map>
#include <cmath>
#include <random>

#include <unistd.h>
#include <ctime>

#include <yara.h>
#include <openssl/sha.h>
#include <curl/curl.h>

namespace fs = std::filesystem;

constexpr const char* SPYDER_VERSION = "4.0.2";

// ==================== CATÁLOGO DE INSULTOS A VIRUS ====================
static const std::vector<std::string> VIRUS_INSULTS = {
    "¡Te pillé, virus barato!",
    "¡Anda y vete de mi sistema, troyano de pacotilla!",
    "Eres más inútil que tu creador, malware.",
    "¡Fuera de aquí, gusano molesto!",
    "Spyder te acaba de dar una paliza, sinvergüenza.",
    "Malware de segunda, lárgate de mi PC.",
    "¡Qué patético eres, ransomware de pacotilla!",
    "Spyder te dice: chao, perdedor.",
    "Eres tan débil que da vergüenza.",
    "¡Vete por donde viniste, parásito digital!",
    "¡Te detecté y te humillé, virus!",
    "Este código es más tóxico que tú.",
    "¡Muérete en la cuarentena, troyano!",
    "Keylogger de pacotilla, fuera de mi sistema.",
    "Eres más flojo que un virus de principiante.",
    "¡Te pilló Spyder, fracasado!",
    "Virus de tercera, te voy a borrar del mapa.",
    "¡Anda a esconderte al agujero de donde saliste!",
    "Spyder te ha dado más palizas que tu creador.",
    "¡Adiós, malware de baja calidad!",
    "Eres la vergüenza del mundo del malware.",
    "¡Qué ridículo eres, troyano!",
    "Más viejo e inútil que Windows Vista.",
    "¡Que te metan un buen delete, inútil!",
    "Spyder te dice: chúpate esa, virus.",
    "Malware de pacotilla, vete a dormir.",
    "¡Ni encriptar sabes, ransomware novato!",
    "¡Vuelve al basurero digital, basura!",
    "Eres tan obvio que cualquiera te detecta.",
    "¡Muere en la cuarentena, parásito!",
    "Virus más flojo que un antivirus gratis.",
    "¡Te mando directo a la papelera, perdedor!"
};

static std::string get_random_insult() {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<size_t> dist(0, VIRUS_INSULTS.size() - 1);
    return VIRUS_INSULTS[dist(rng)];
}

// ==================== YARA RULES ====================
static const char* YARA_RULES = R"YARA(
rule EICAR_Test {
    strings: $a = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D }
    condition: $a at 0
}

rule High_Entropy_Packed {
    condition: filesize > 100KB and filesize < 10MB and math.entropy(0, filesize) > 7.5
}
)YARA";

// ==================== COLORS ====================
namespace Color {
    bool enabled = true;
    std::string red(const std::string& s)    { return enabled ? "\033[31m" + s + "\033[0m" : s; }
    std::string green(const std::string& s)  { return enabled ? "\033[32m" + s + "\033[0m" : s; }
    std::string yellow(const std::string& s) { return enabled ? "\033[33m" + s + "\033[0m" : s; }
    std::string cyan(const std::string& s)   { return enabled ? "\033[36m" + s + "\033[0m" : s; }
    std::string bold(const std::string& s)   { return enabled ? "\033[1m"  + s + "\033[0m" : s; }
}

// ==================== RAII YARA ====================
struct YaraInit {
    YaraInit()  { if (yr_initialize() != ERROR_SUCCESS) throw std::runtime_error("YARA init failed"); }
    ~YaraInit() { yr_finalize(); }
};

// FIX #7: YaraRules is now compiled once and shared across threads (read-only after construction).
class YaraRules {
    YR_RULES* rules = nullptr;
public:
    explicit YaraRules(const char* source);
    ~YaraRules() { if (rules) yr_rules_destroy(rules); }

    // Non-copyable, non-movable to prevent double-free.
    YaraRules(const YaraRules&)            = delete;
    YaraRules& operator=(const YaraRules&) = delete;

    YR_RULES* get() const { return rules; }
};

// ==================== UTILITIES ====================
static std::string calculate_sha256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "ERROR";

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    std::vector<unsigned char> buf(65536);
    while (file.read(reinterpret_cast<char*>(buf.data()), buf.size()) || file.gcount() > 0)
        SHA256_Update(&ctx, buf.data(), static_cast<size_t>(file.gcount()));

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (unsigned char b : hash)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

static double file_entropy(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return 0.0;

    std::array<uint64_t, 256> freq{};
    freq.fill(0);
    uint64_t total = 0;

    char c;
    while (file.get(c)) {
        freq[static_cast<unsigned char>(c)]++;
        total++;
    }

    if (total == 0) return 0.0;

    double entropy = 0.0;
    for (uint64_t count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ==================== HASH CACHE ====================
class HashCache {
    std::unordered_map<std::string, int> store;
    std::mutex mtx;
    fs::path cache_file;
    bool dirty = false; // FIX #6: track whether a save is needed

    void load() {
        std::ifstream f(cache_file);
        std::string hash; int val;
        while (f >> hash >> val) store[hash] = val;
    }

    // FIX #6: save() is now private and only called explicitly via flush().
    void save() {
        std::ofstream f(cache_file, std::ios::trunc);
        for (auto& [h, v] : store) f << h << " " << v << "\n";
        dirty = false;
    }

public:
    HashCache() {
        const char* home = getenv("HOME");
        cache_file = home ? fs::path(home) / ".spyder" / "hashcache.db"
                          : "/var/lib/spyder/hashcache.db";
        fs::create_directories(cache_file.parent_path());
        load();
    }

    // FIX #6: flush() saves the cache to disk once at the end of a scan run.
    ~HashCache() {
        if (dirty) save();
    }

    void flush() {
        std::lock_guard<std::mutex> lock(mtx);
        if (dirty) save();
    }

    int check(const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = store.find(hash);
        return it != store.end() ? it->second : 0;
    }

    void mark_clean(const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx);
        store[hash] = 1;
        dirty = true;  // FIX #6: defer disk write
    }

    void mark_dirty(const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx);
        store[hash] = -1;
        dirty = true;  // FIX #6: defer disk write
    }
};

// ==================== VIRUSTOTAL ====================
class VirusTotal {
    std::string api_key;

    static size_t write_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
        static_cast<std::string*>(userdata)->append(static_cast<char*>(ptr), size * nmemb);
        return size * nmemb;
    }

public:
    explicit VirusTotal(const std::string& key) : api_key(key) {}

    struct VTResult { bool found = false; bool malicious = false; int detections = 0; int total = 0; };

    VTResult check_hash(const std::string& hash) {
        VTResult res;
        CURL* curl = curl_easy_init();
        if (!curl) return res;

        std::string url = "https://www.virustotal.com/api/v3/files/" + hash;
        std::string response;
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("x-apikey: " + api_key).c_str());

        curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);

        CURLcode rc = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (rc != CURLE_OK) return res;

        auto extract = [&](const std::string& key) -> int {
            auto pos = response.find("\"" + key + "\":");
            if (pos == std::string::npos) return -1;
            pos = response.find_first_of("0123456789", pos);
            if (pos == std::string::npos) return -1;
            return std::stoi(response.substr(pos));
        };

        int mal   = extract("malicious");
        int total = extract("total");
        if (mal >= 0) {
            res.found      = true;
            res.malicious  = (mal > 0);
            res.detections = mal;
            res.total      = total >= 0 ? total : 0;
        }
        return res;
    }
};

// ==================== VT RATE LIMITER ====================
// FIX #2 & #4: Encapsulate VT throttle state so it can be locked/unlocked cleanly,
// releasing the mutex before sleeping instead of holding it for up to 60 s.
struct VTRateLimiter {
    std::mutex mtx;
    int calls = 0;
    std::chrono::steady_clock::time_point window_start = std::chrono::steady_clock::now();

    void acquire() {
        while (true) {
            std::chrono::milliseconds sleep_for{0};
            {
                std::lock_guard<std::mutex> lock(mtx);
                auto now     = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - window_start).count();
                if (elapsed >= 60) {
                    calls        = 0;
                    window_start = now;
                }
                if (calls < 4) {
                    ++calls;
                    return; // slot acquired — exit holding no lock
                }
                // FIX #2: compute wait time, then release the lock BEFORE sleeping
                auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(now - window_start);
                sleep_for   = std::chrono::milliseconds(60000) - waited + std::chrono::milliseconds(10);
            }
            // Sleep outside the lock so other threads aren't blocked
            std::this_thread::sleep_for(sleep_for);
        }
    }
};

// ==================== QUARANTINE ====================
class Quarantine {
    fs::path qdir;
    std::mutex mtx;
    std::atomic<uint64_t> counter{0};

public:
    Quarantine() {
        const char* home = getenv("HOME");
        qdir = home ? fs::path(home) / ".spyder" / "quarantine"
                    : "/var/lib/spyder/quarantine";
        fs::create_directories(qdir);
    }

    std::string quarantine_file(const std::string& src) {
        std::lock_guard<std::mutex> lock(mtx);
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        std::string dst = (qdir / (std::to_string(now) + "_" + std::to_string(counter++) + "_"
                         + fs::path(src).filename().string() + ".quar")).string();
        try {
            fs::rename(src, dst);
            std::cout << Color::green("[+] Cuarentena: ") << fs::path(dst).filename() << "\n";
            return dst;
        } catch (...) {
            std::cout << Color::yellow("[!] Fallo al cuarentenar: ") << src << "\n";
            return "";
        }
    }

    void list() {
        std::cout << Color::bold("\n📦 Cuarentena:\n");
        for (auto& e : fs::directory_iterator(qdir))
            if (e.path().extension() == ".quar")
                std::cout << " " << e.path().filename() << "\n";
    }
};

// ==================== SCAN RESULT ====================
struct ScanResult {
    std::string filepath, verdict = "clean", action = "none";
    bool yara_hit = false;
};

// ==================== SPYDER CORE ====================
class Spyder {
    bool verbose;
    // FIX #7: YARA rules compiled once, shared read-only across all threads.
    YaraRules shared_rules;
public:
    explicit Spyder(bool v = true)
        : verbose(v), shared_rules(YARA_RULES)
    {
        if (verbose)
            std::cout << Color::bold("🐍 Spyder Anti-Virus v") << SPYDER_VERSION << "\n\n";
    }

    ScanResult analyze(const std::string& path, bool qmode, bool dmode,
                       Quarantine& quarantine, HashCache& cache,
                       VirusTotal* vt, VTRateLimiter* limiter,
                       std::mutex& cout_mtx);
};

// ==================== YARARULES IMPL ====================
YaraRules::YaraRules(const char* source) {
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        throw std::runtime_error("Fallo al crear compilador YARA");

    if (yr_compiler_add_string(compiler, source, nullptr) != 0) {
        yr_compiler_destroy(compiler);
        throw std::runtime_error("Fallo al compilar reglas YARA");
    }

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        throw std::runtime_error("Fallo al obtener reglas YARA compiladas");
    }

    yr_compiler_destroy(compiler);
}

// ==================== YARA CALLBACK ====================
struct YaraCallbackData { bool hit = false; std::string rule_name; };

static int yara_callback(YR_SCAN_CONTEXT*, int message, void* data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* cbd  = static_cast<YaraCallbackData*>(user_data);
        auto* rule = static_cast<YR_RULE*>(data);
        cbd->hit       = true;
        cbd->rule_name = rule->identifier;
    }
    return CALLBACK_CONTINUE;
}

// ==================== SPYDER::ANALYZE IMPL ====================
ScanResult Spyder::analyze(const std::string& path, bool qmode, bool dmode,
                            Quarantine& quarantine, HashCache& cache,
                            VirusTotal* vt, VTRateLimiter* limiter,
                            std::mutex& cout_mtx) {
    ScanResult result;
    result.filepath = path;

    double entropy    = file_entropy(path);
    bool high_entropy = (entropy > 7.2);
    std::string hash  = calculate_sha256(path);
    result.verdict    = "clean";

    int cached = cache.check(hash);
    if (cached == 1 && !high_entropy) {
        if (verbose) {
            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout << Color::green("[CACHE] ")
                      << fs::path(path).filename().string() << " — clean (cached)\n";
        }
        return result;
    }
    if (cached == -1) {
        result.verdict  = "malware [cached]";
        result.yara_hit = true;
    }

    // FIX #7: use pre-compiled shared_rules instead of recompiling per file.
    if (result.verdict == "clean") {
        YaraCallbackData cbd;
        int scan_res = yr_rules_scan_file(shared_rules.get(), path.c_str(), 0,
                                          yara_callback, &cbd, 0);
        if (scan_res == ERROR_SUCCESS && cbd.hit) {
            result.yara_hit = true;
            result.verdict  = "malware [YARA:" + cbd.rule_name + "]";
        }
    }

    if (vt && limiter && result.verdict == "clean") {
        limiter->acquire();  // FIX #2: throttle outside any other lock
        auto vtr = vt->check_hash(hash);
        if (vtr.found && vtr.malicious) {
            result.verdict  = "malware [VT:" + std::to_string(vtr.detections)
                              + "/" + std::to_string(vtr.total) + "]";
            result.yara_hit = true;
        }
    }

    if (high_entropy && result.verdict == "clean")
        result.verdict = "suspicious [entropy:" + std::to_string(entropy).substr(0, 4) + "]";

    bool is_threat = (result.verdict != "clean");

    if (verbose) {
        std::lock_guard<std::mutex> lock(cout_mtx);
        std::string icon = is_threat ? Color::red("[!]") : Color::green("[OK]");
        std::cout << icon << " " << Color::cyan(fs::path(path).filename().string())
                  << " — " << result.verdict << "\n";
        if (!hash.empty())
            std::cout << " SHA256: " << hash << "\n";
        if (is_threat)
            std::cout << Color::red(" 🕷️ Spyder dice: ")
                      << Color::bold(get_random_insult()) << "\n";
    }

    if (is_threat) {
        if (qmode) {
            result.action = quarantine.quarantine_file(path);
        } else if (dmode) {
            try {
                fs::remove(path);
                result.action = "deleted";
                std::lock_guard<std::mutex> lock(cout_mtx);
                std::cout << Color::red("[-] Eliminado: ") << path << "\n";
            } catch (...) {
                std::lock_guard<std::mutex> lock(cout_mtx);
                std::cout << Color::yellow("[!] No se pudo eliminar: ") << path << "\n";
            }
        }
    }

    if (result.verdict == "clean")
        cache.mark_clean(hash);
    else if (result.yara_hit)
        cache.mark_dirty(hash);

    return result;
}

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    try {
        YaraInit yara_init;
        Quarantine quarantine;
        HashCache cache;

        bool qmode = false, dmode = false, quiet = false, list_quar = false;
        std::string path, vt_key;

        const size_t MAX_THREADS = 16;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if      (arg == "-q" || arg == "--quarantine")  qmode     = true;
            else if (arg == "--delete")                      dmode     = true;
            else if (arg == "--quiet")                       quiet     = true;
            else if (arg == "--list-quarantine")             list_quar = true;
            else if (arg == "--vt-key" && i + 1 < argc)     vt_key    = argv[++i];
            else if (arg == "-h" || arg == "--help") {
                std::cout << R"LOGO(
  ____ ____ _ _ ____ ____ ____
 / ___)( _ \( \/ )( _ \( ___)( _ \
 \___ \ )___/ \ / )(_) ))__) ) /
 (____/(__) (__) (____/(____)(_)\_)
   Anti-Malware Engine v4.0.2 🕷️
   Built by 5 AIs | github.com/spyder-av
)LOGO";
                return 0;
            }
            else path = arg;
        }

        Color::enabled = !quiet;

        if (list_quar) { quarantine.list(); return 0; }
        if (path.empty()) {
            std::cout << "Ruta: ";
            std::getline(std::cin, path);
        }

        if (!fs::exists(path)) {
            std::cerr << Color::red("[-] Ruta no encontrada.\n");
            return 1;
        }

        std::vector<std::string> files;
        if (fs::is_directory(path)) {
            for (auto& e : fs::recursive_directory_iterator(path))
                if (e.is_regular_file()) files.push_back(e.path().string());
        } else {
            files.push_back(path);
        }

        std::cout << Color::bold("[*] Archivos: ") << files.size()
                  << " | Hilos máximos: " << MAX_THREADS << "\n\n";

        // FIX #7: Spyder constructor now compiles YARA rules once.
        Spyder spy(!quiet);
        std::unique_ptr<VirusTotal>    vt      = vt_key.empty() ? nullptr : std::make_unique<VirusTotal>(vt_key);
        std::unique_ptr<VTRateLimiter> limiter = vt ? std::make_unique<VTRateLimiter>() : nullptr;

        std::mutex cout_mtx;
        std::atomic<size_t> completed{0};

        // Sliding-window executor: keep at most MAX_THREADS futures in-flight.
        // `drain_idx` tracks which future to drain next (always in submission order),
        // so we never call .get() on an already-drained future (Bug A fix).
        // The in-flight count is computed with signed arithmetic to avoid unsigned
        // underflow (Bug B fix).
        // `submitted` variable removed — it was dead code (Bug C fix).
        std::vector<std::future<ScanResult>> futures;
        futures.reserve(files.size());
        size_t drain_idx = 0;

        for (const auto& f : files) {
            // Drain oldest future when the window is full.
            // Cast to ptrdiff_t to avoid unsigned underflow if drain_idx ever
            // races ahead (should not happen, but belt-and-suspenders).
            while (static_cast<ptrdiff_t>(futures.size()) - static_cast<ptrdiff_t>(drain_idx)
                   >= static_cast<ptrdiff_t>(MAX_THREADS)) {
                futures[drain_idx++].get();
            }

            futures.push_back(std::async(std::launch::async,
                [&spy, &quarantine, &cache, &vt, &limiter, &cout_mtx, &completed, &files,
                 quiet, qmode, dmode, f]()
                {
                    ScanResult res = spy.analyze(f, qmode, dmode,
                                                 quarantine, cache,
                                                 vt.get(), limiter.get(),
                                                 cout_mtx);
                    size_t n = ++completed;
                    if (!quiet) {
                        std::lock_guard<std::mutex> lock(cout_mtx);
                        std::cout << "\rProgreso: " << n << "/" << files.size() << "   " << std::flush;
                    }
                    return res;
                }
            ));
        }

        // Drain remaining futures in submission order.
        for (; drain_idx < futures.size(); ++drain_idx)
            futures[drain_idx].get();

        // FIX #6: Flush the hash cache to disk once, after all scans complete.
        cache.flush();

        std::cout << "\n\n" << Color::bold("¡Escaneo completado! 🕷️\n");
        return 0;

    } catch (const std::exception& e) {
        std::cerr << Color::red("Error: ") << e.what() << '\n';
        return 1;
    }
}
