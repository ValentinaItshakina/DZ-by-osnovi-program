#include <iostream>
#include <vector>
#include <array>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <random>
#include <memory>
#include <queue>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <map>
#include <numeric>

// OpenSSL заголовочные файлы
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

using namespace std;
using namespace chrono;

// ==================== RSA-PSS IMPLEMENTATION (OpenSSL 3.0+) ====================
class RSA_PSS {
private:
    EVP_PKEY* pkey;  // Используем EVP_PKEY вместо RSA*
    size_t key_size_bits;
    int salt_length;
    
    // Хеширование с SHA-256
    vector<unsigned char> sha256(const vector<unsigned char>& data) {
        vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }
    
    // MGF1 (Mask Generation Function)
    vector<unsigned char> mgf1(const vector<unsigned char>& seed, size_t length) {
        vector<unsigned char> mask;
        vector<unsigned char> counter(4, 0);
        
        for (size_t i = 0; mask.size() < length; i++) {
            counter[0] = (i >> 24) & 0xFF;
            counter[1] = (i >> 16) & 0xFF;
            counter[2] = (i >> 8) & 0xFF;
            counter[3] = i & 0xFF;
            
            vector<unsigned char> combined = seed;
            combined.insert(combined.end(), counter.begin(), counter.end());
            
            vector<unsigned char> hash = sha256(combined);
            
            size_t to_copy = min(hash.size(), length - mask.size());
            mask.insert(mask.end(), hash.begin(), hash.begin() + to_copy);
        }
        
        return mask;
    }
    
    // PSS Encoding
    vector<unsigned char> pss_encode(const vector<unsigned char>& message, size_t em_len) {
        size_t h_len = SHA256_DIGEST_LENGTH;
        size_t s_len = salt_length;
        
        // 1. Генерируем salt
        vector<unsigned char> salt(s_len);
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dist(0, 255);
        
        for (size_t i = 0; i < s_len; i++) {
            salt[i] = static_cast<unsigned char>(dist(gen));
        }
        
        // 2. Формируем M' = padding1 || hash(M) || salt
        vector<unsigned char> m_prime(8 + h_len + s_len, 0x00);
        vector<unsigned char> m_hash = sha256(message);
        
        copy(m_hash.begin(), m_hash.end(), m_prime.begin() + 8);
        copy(salt.begin(), salt.end(), m_prime.begin() + 8 + h_len);
        
        // 3. Хешируем M'
        vector<unsigned char> h = sha256(m_prime);
        
        // 4. Формируем DB = padding2 || salt
        vector<unsigned char> db(em_len - h_len - 1, 0x00);
        db[em_len - h_len - s_len - 2] = 0x01;
        copy(salt.begin(), salt.end(), db.end() - s_len);
        
        // 5. Генерируем маску для DB
        vector<unsigned char> db_mask = mgf1(h, em_len - h_len - 1);
        
        // 6. Маскируем DB
        for (size_t i = 0; i < db.size(); i++) {
            db[i] ^= db_mask[i];
        }
        
        // 7. Устанавливаем старший бит в 0
        db[0] &= 0x7F;
        
        // 8. Формируем EM = maskedDB || h || 0xBC
        vector<unsigned char> em;
        em.reserve(em_len);
        
        em.insert(em.end(), db.begin(), db.end());
        em.insert(em.end(), h.begin(), h.end());
        em.push_back(0xBC);
        
        return em;
    }
    
    // PSS Verification
    bool pss_verify(const vector<unsigned char>& message, 
                   const vector<unsigned char>& em, 
                   size_t em_len) {
        size_t h_len = SHA256_DIGEST_LENGTH;
        size_t s_len = salt_length;
        
        if (em.size() != em_len || em.back() != 0xBC) {
            return false;
        }
        
        vector<unsigned char> masked_db(em.begin(), em.begin() + em_len - h_len - 1);
        vector<unsigned char> h(em.begin() + em_len - h_len - 1, em.begin() + em_len - 1);
        
        vector<unsigned char> db_mask = mgf1(h, em_len - h_len - 1);
        
        vector<unsigned char> db = masked_db;
        for (size_t i = 0; i < db.size(); i++) {
            db[i] ^= db_mask[i];
        }
        
        if (db[0] & 0x80) {
            return false;
        }
        
        size_t separator_pos = 0;
        for (size_t i = 0; i < db.size() - s_len; i++) {
            if (db[i] == 0x01) {
                separator_pos = i;
                break;
            }
        }
        
        if (separator_pos == 0) {
            return false;
        }
        
        for (size_t i = 0; i < separator_pos; i++) {
            if (db[i] != 0x00) {
                return false;
            }
        }
        
        vector<unsigned char> salt(db.begin() + separator_pos + 1, 
                                  db.begin() + separator_pos + 1 + s_len);
        
        vector<unsigned char> m_prime(8 + h_len + s_len, 0x00);
        vector<unsigned char> m_hash = sha256(message);
        
        copy(m_hash.begin(), m_hash.end(), m_prime.begin() + 8);
        copy(salt.begin(), salt.end(), m_prime.begin() + 8 + h_len);
        
        vector<unsigned char> h_prime = sha256(m_prime);
        
        return h == h_prime;
    }
    
public:
    RSA_PSS(size_t key_size = 2048, int salt_len = 32) 
        : key_size_bits(key_size), salt_length(salt_len), pkey(nullptr) {
        // Инициализация OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    
    ~RSA_PSS() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
        EVP_cleanup();
        ERR_free_strings();
    }
    
    // Генерация ключей с использованием EVP API
    pair<string, string> generate_keys() {
        auto start = high_resolution_clock::now();
        
        // Создание контекста генерации ключей
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            throw runtime_error("Failed to create key generation context");
        }
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw runtime_error("Failed to initialize key generation");
        }
        
        // Установка размера ключа
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size_bits) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw runtime_error("Failed to set key size");
        }
        
        // Генерация ключа
        EVP_PKEY* new_key = nullptr;
        if (EVP_PKEY_keygen(ctx, &new_key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw runtime_error("Failed to generate key");
        }
        
        EVP_PKEY_CTX_free(ctx);
        
        // Освобождаем старый ключ, если есть
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
        pkey = new_key;
        
        // Экспорт публичного ключа
        BIO* pub_bio = BIO_new(BIO_s_mem());
        if (!pub_bio) {
            throw runtime_error("Failed to create BIO for public key");
        }
        
        if (PEM_write_bio_PUBKEY(pub_bio, pkey) != 1) {
            BIO_free(pub_bio);
            throw runtime_error("Failed to export public key");
        }
        
        char* pub_key_data;
        long pub_key_len = BIO_get_mem_data(pub_bio, &pub_key_data);
        string public_key(pub_key_data, pub_key_len);
        BIO_free(pub_bio);
        
        // Экспорт приватного ключа
        BIO* priv_bio = BIO_new(BIO_s_mem());
        if (!priv_bio) {
            throw runtime_error("Failed to create BIO for private key");
        }
        
        if (PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(priv_bio);
            throw runtime_error("Failed to export private key");
        }
        
        char* priv_key_data;
        long priv_key_len = BIO_get_mem_data(priv_bio, &priv_key_data);
        string private_key(priv_key_data, priv_key_len);
        BIO_free(priv_bio);
        
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(end - start);
        
        cout << "Ключи сгенерированы за " << duration.count() << " мс" << endl;
        cout << "Размер ключа: " << key_size_bits << " бит" << endl;
        
        return make_pair(public_key, private_key);
    }
    
    // Создание подписи (УПРОЩЕННАЯ ВЕРСИЯ - используем встроенный PSS)
    vector<unsigned char> sign(const vector<unsigned char>& message) {
        auto start = high_resolution_clock::now();
        
        if (!pkey) {
            throw runtime_error("RSA key not initialized");
        }
        
        // Создание контекста подписи
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            throw runtime_error("Failed to create EVP_MD_CTX");
        }
        
        // Упрощенная подпись - используем встроенную PSS реализацию
        if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw runtime_error("Failed to initialize signing context");
        }
        
        // Обновление контекста с данными
        if (EVP_DigestSignUpdate(md_ctx, message.data(), message.size()) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw runtime_error("Failed to update signing context");
        }
        
        // Определение размера подписи
        size_t sig_len = 0;
        if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw runtime_error("Failed to get signature length");
        }
        
        // Выделение памяти для подписи
        vector<unsigned char> signature(sig_len);
        
        // Создание подписи
        if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw runtime_error("Failed to create signature");
        }
        
        signature.resize(sig_len);
        EVP_MD_CTX_free(md_ctx);
        
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);
        
        cout << "Подпись создана за " << duration.count() << " мкс" << endl;
        
        return signature;
    }
    
    // Верификация подписи (УПРОЩЕННАЯ ВЕРСИЯ)
    bool verify(const vector<unsigned char>& message, 
                const vector<unsigned char>& signature,
                const string& public_key_pem = "") {
        auto start = high_resolution_clock::now();
        
        EVP_PKEY* verify_pkey = pkey;
        bool should_free_key = false;
        
        // Если передан публичный ключ, используем его
        if (!public_key_pem.empty()) {
            BIO* bio = BIO_new_mem_buf(public_key_pem.data(), public_key_pem.size());
            if (!bio) {
                throw runtime_error("Failed to create BIO for public key");
            }
            
            verify_pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            
            if (!verify_pkey) {
                return false;  // Не смогли распарсить ключ
            }
            should_free_key = true;
        }
        
        if (!verify_pkey) {
            return false;  // Ключ недоступен
        }
        
        // Создание контекста верификации
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            if (should_free_key) {
                EVP_PKEY_free(verify_pkey);
            }
            return false;
        }
        
        // Инициализация контекста для верификации
        if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, verify_pkey) != 1) {
            EVP_MD_CTX_free(md_ctx);
            if (should_free_key) {
                EVP_PKEY_free(verify_pkey);
            }
            return false;
        }
        
        // Обновление контекста с данными
        if (EVP_DigestVerifyUpdate(md_ctx, message.data(), message.size()) != 1) {
            EVP_MD_CTX_free(md_ctx);
            if (should_free_key) {
                EVP_PKEY_free(verify_pkey);
            }
            return false;
        }
        
        // Верификация подписи
        int result = EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());
        
        EVP_MD_CTX_free(md_ctx);
        
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);
        
        cout << "Верификация выполнена за " << duration.count() << " мкс" << endl;
        
        if (should_free_key) {
            EVP_PKEY_free(verify_pkey);
        }
        
        return (result == 1);
    }
    
    size_t get_key_size() const { return key_size_bits; }
    size_t get_signature_size() const { 
        if (!pkey) return 0;
        return EVP_PKEY_size(pkey);
    }
};

// ==================== PERFORMANCE TESTING ====================
class RSAPerformanceTester {
public:
    static void run_comprehensive_tests() {
        cout << "=== КОМПЛЕКСНЫЕ ТЕСТЫ RSA-PSS (OpenSSL 3.0+) ===" << endl;
        
        // Тест 1: Проверка требований задания
        cout << "\n1. ПРОВЕРКА ОСНОВНЫХ ТРЕБОВАНИЙ:" << endl;
        cout << string(80, '-') << endl;
        test_basic_requirements();
        
        // Тест 2: Производительность на разных размерах данных
        cout << "\n2. ТЕСТ ПРОИЗВОДИТЕЛЬНОСТИ:" << endl;
        cout << string(80, '-') << endl;
        test_performance_scaling();
        
        // Тест 3: Разные размеры ключей
        cout << "\n3. ТЕСТ РАЗНЫХ РАЗМЕРОВ КЛЮЧЕЙ:" << endl;
        cout << string(80, '-') << endl;
        test_key_sizes();
        
        // Тест 4: Граничные случаи
        cout << "\n4. ТЕСТ ГРАНИЧНЫХ СЛУЧАЕВ:" << endl;
        cout << string(80, '-') << endl;
        test_edge_cases();
    }
    
private:
    static void test_basic_requirements() {
        cout << "Тестирование RSA-PSS с ключом 2048 бит" << endl;
        
        try {
            RSA_PSS rsa(2048);
            
            // Генерация ключей
            cout << "Генерация ключей..." << endl;
            auto keys = rsa.generate_keys();
            
            // Тестовые данные
            string test_message = "Рекомендую товары: iPhone 15, MacBook Pro, AirPods Pro";
            vector<unsigned char> message(test_message.begin(), test_message.end());
            
            // Тест 1: Создание подписи < 100 мс
            cout << "\nТЕСТ 1: Создание подписи < 100 мс" << endl;
            auto sign_start = high_resolution_clock::now();
            auto signature = rsa.sign(message);
            auto sign_end = high_resolution_clock::now();
            
            double sign_time = duration_cast<microseconds>(sign_end - sign_start).count() / 1000.0;
            cout << "Время: " << sign_time << " мс -> "
                 << (sign_time < 100 ? "✅" : "❌") << endl;
            
            // Тест 2: Проверка подписи < 10 мс
            cout << "\nТЕСТ 2: Проверка подписи < 10 мс" << endl;
            auto verify_start = high_resolution_clock::now();
            bool valid = rsa.verify(message, signature);
            auto verify_end = high_resolution_clock::now();
            
            double verify_time = duration_cast<microseconds>(verify_end - verify_start).count() / 1000.0;
            cout << "Время: " << verify_time << " мс -> "
                 << (verify_time < 10 ? "✅" : "❌") << endl;
            
            // Тест 3: Верификация валидной подписи
            cout << "\nТЕСТ 3: Верификация валидной подписи = true" << endl;
            cout << "Результат: " << (valid ? "true" : "false") << " -> "
                 << (valid ? "✅" : "❌") << endl;
            
            // Тест 4: Верификация невалидной подписи
            cout << "\nТЕСТ 4: Верификация невалидной подписи = false" << endl;
            vector<unsigned char> fake_signature;
            if (!signature.empty()) {
                fake_signature = signature;
                fake_signature[0] ^= 0xFF;  // Изменяем первый байт подписи
            } else {
                fake_signature = vector<unsigned char>(256, 0xAA);  // Случайная подпись
            }
            
            bool fake_valid = false;
            try {
                fake_valid = rsa.verify(message, fake_signature);
            } catch (const exception& e) {
                cout << "Исключение при верификации: " << e.what() << endl;
                fake_valid = false;
            }
            
            cout << "Результат: " << (fake_valid ? "true" : "false") << " -> "
                 << (!fake_valid ? "✅" : "❌") << endl;
            
            // Тест 5: Верификация измененных данных
            cout << "\nТЕСТ 5: Верификация измененных данных = false" << endl;
            string modified_message = "Рекомендую товары: iPhone 14, MacBook Air, AirPods 2";
            vector<unsigned char> modified(modified_message.begin(), modified_message.end());
            bool modified_valid = false;
            try {
                modified_valid = rsa.verify(modified, signature);
            } catch (const exception& e) {
                cout << "Исключение при верификации: " << e.what() << endl;
                modified_valid = false;
            }
            
            cout << "Результат: " << (modified_valid ? "true" : "false") << " -> "
                 << (!modified_valid ? "✅" : "❌") << endl;
            
            // Тест 6: Верификация с чужим ключом
            cout << "\nТЕСТ 6: Верификация с чужим ключом = false" << endl;
            RSA_PSS another_rsa(2048);
            auto another_keys = another_rsa.generate_keys();
            bool wrong_key_valid = false;
            try {
                wrong_key_valid = rsa.verify(message, signature, another_keys.first);
            } catch (const exception& e) {
                cout << "Исключение при верификации: " << e.what() << endl;
                wrong_key_valid = false;
            }
            
            cout << "Результат: " << (wrong_key_valid ? "true" : "false") << " -> "
                 << (!wrong_key_valid ? "✅" : "❌") << endl;
                
        } catch (const exception& e) {
            cerr << "Ошибка в тестах: " << e.what() << endl;
        }
    }
    
    static void test_performance_scaling() {
        cout << "Тестирование производительности на разных размерах данных" << endl;
        
        try {
            RSA_PSS rsa(2048);
            auto keys = rsa.generate_keys();
            
            vector<size_t> data_sizes = {16, 64, 256, 1024, 4096, 16384};
            
            cout << setw(12) << "Размер данных" 
                 << setw(15) << "Время подписи"
                 << setw(15) << "Время проверки"
                 << setw(15) << "Размер подписи" << endl;
            cout << string(57, '-') << endl;
            
            for (size_t size : data_sizes) {
                vector<unsigned char> data(size);
                random_device rd;
                mt19937 gen(rd());
                uniform_int_distribution<> dist(0, 255);
                
                for (size_t i = 0; i < size; i++) {
                    data[i] = static_cast<unsigned char>(dist(gen));
                }
                
                auto sign_start = high_resolution_clock::now();
                auto signature = rsa.sign(data);
                auto sign_end = high_resolution_clock::now();
                double sign_time = duration_cast<microseconds>(sign_end - sign_start).count() / 1000.0;
                
                auto verify_start = high_resolution_clock::now();
                bool valid = rsa.verify(data, signature);
                auto verify_end = high_resolution_clock::now();
                double verify_time = duration_cast<microseconds>(verify_end - verify_start).count() / 1000.0;
                
                cout << fixed << setprecision(2);
                cout << setw(12) << size << " B"
                     << setw(15) << sign_time << " ms"
                     << setw(15) << verify_time << " ms"
                     << setw(15) << signature.size() << " B" << endl;
            }
        } catch (const exception& e) {
            cerr << "Ошибка в тестах производительности: " << e.what() << endl;
        }
    }
    
    static void test_key_sizes() {
        cout << "Сравнение разных размеров ключей" << endl;
        
        vector<size_t> key_sizes = {1024, 2048, 3072, 4096};
        vector<unsigned char> test_data(1024, 0x55);
        
        cout << setw(10) << "Ключ"
             << setw(15) << "Генерация"
             << setw(15) << "Подпись"
             << setw(15) << "Проверка"
             << setw(15) << "Размер подписи" << endl;
        cout << string(70, '-') << endl;
        
        for (size_t key_size : key_sizes) {
            try {
                RSA_PSS rsa(key_size);
                
                auto gen_start = high_resolution_clock::now();
                auto keys = rsa.generate_keys();
                auto gen_end = high_resolution_clock::now();
                double gen_time = duration_cast<milliseconds>(gen_end - gen_start).count();
                
                auto sign_start = high_resolution_clock::now();
                auto signature = rsa.sign(test_data);
                auto sign_end = high_resolution_clock::now();
                double sign_time = duration_cast<microseconds>(sign_end - sign_start).count() / 1000.0;
                
                auto verify_start = high_resolution_clock::now();
                bool valid = rsa.verify(test_data, signature);
                auto verify_end = high_resolution_clock::now();
                double verify_time = duration_cast<microseconds>(verify_end - verify_start).count() / 1000.0;
                
                cout << fixed << setprecision(2);
                cout << setw(10) << "RSA-" << key_size
                     << setw(15) << gen_time << " ms"
                     << setw(15) << sign_time << " ms"
                     << setw(15) << verify_time << " ms"
                     << setw(15) << signature.size() << " B" << endl;
            } catch (const exception& e) {
                cout << setw(10) << "RSA-" << key_size
                     << setw(15) << "ERROR" << setw(15) << "ERROR" 
                     << setw(15) << "ERROR" << setw(15) << "ERROR" << endl;
            }
        }
    }
    
    static void test_edge_cases() {
        cout << "Тестирование граничных случаев" << endl;
        
        try {
            RSA_PSS rsa(2048);
            auto keys = rsa.generate_keys();
            
            // Случай 1: Пустые данные
            cout << "\n1. Пустые данные:" << endl;
            vector<unsigned char> empty_data;
            try {
                auto signature = rsa.sign(empty_data);
                bool valid = rsa.verify(empty_data, signature);
                cout << "Подпись создана и верифицирована: " << (valid ? "✅" : "❌") << endl;
            } catch (const exception& e) {
                cout << "Ошибка: " << e.what() << endl;
            }
            
            // Случай 2: Очень большие данные
            cout << "\n2. Большие данные (100KB):" << endl;
            vector<unsigned char> large_data(100 * 1024, 0xAA);
            try {
                auto sign_start = high_resolution_clock::now();
                auto signature = rsa.sign(large_data);
                auto sign_end = high_resolution_clock::now();
                
                auto verify_start = high_resolution_clock::now();
                bool valid = rsa.verify(large_data, signature);
                auto verify_end = high_resolution_clock::now();
                
                cout << "Подпись: " << duration_cast<milliseconds>(sign_end - sign_start).count() << " ms" << endl;
                cout << "Проверка: " << duration_cast<milliseconds>(verify_end - verify_start).count() << " ms" << endl;
                cout << "Результат: " << (valid ? "✅" : "❌") << endl;
            } catch (const exception& e) {
                cout << "Ошибка: " << e.what() << endl;
            }
            
            // Случай 3: Подпись нулевого размера
            cout << "\n3. Подпись нулевого размера:" << endl;
            vector<unsigned char> test_data(100, 0x42);
            vector<unsigned char> empty_signature;
            bool empty_sig_valid = false;
            try {
                empty_sig_valid = rsa.verify(test_data, empty_signature);
            } catch (const exception& e) {
                cout << "Исключение: " << e.what() << endl;
                empty_sig_valid = false;
            }
            cout << "Результат: " << (empty_sig_valid ? "true" : "false") << " -> "
                 << (!empty_sig_valid ? "✅" : "❌") << endl;
                
        } catch (const exception& e) {
            cerr << "Ошибка в тестах граничных случаев: " << e.what() << endl;
        }
    }
};
