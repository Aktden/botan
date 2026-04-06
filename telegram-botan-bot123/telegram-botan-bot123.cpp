#include <botan/aes.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/hex.h>
#include <iostream>
#include <string>
#include <sstream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

const std::string BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"; // Замените на реальный токен
const std::string TELEGRAM_API = "https://api.telegram.org/bot" + BOT_TOKEN + "/";

// Callback для CURL
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

// Отправка HTTP GET запроса
std::string httpGet(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

// Отправка сообщения
void sendMessage(const std::string& chatId, const std::string& text) {
    std::string url = TELEGRAM_API + "sendMessage?chat_id=" + chatId + "&text=" + curl_easy_escape(nullptr, text.c_str(), 0);
    httpGet(url);
}

// Шифрование с Botan
std::string encryptMessage(const std::string& plaintext) {
    try {
        Botan::AutoSeeded_RNG rng;
        const std::string keyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"; // 32 байта
        const std::vector<uint8_t> key = Botan::hex_decode(keyHex);

        auto enc = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        enc->set_key(key);

        std::vector<uint8_t> nonce(12);
        rng.randomize(nonce.data(), nonce.size());
        enc->set_associated_data(nonce); // используем nonce как AD

        std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
        std::vector<uint8_t> ct(pt.size() + enc->output_length(pt.size()));

        enc->start(nonce);
        enc->finish(pt, ct);

        // Формат: nonce + ciphertext + tag
        std::vector<uint8_t> result = nonce;
        result.insert(result.end(), ct.begin(), ct.end());

        return Botan::base64_encode(result);
    }
    catch (const std::exception& e) {
        return "Ошибка шифрования: " + std::string(e.what());
    }
}

// Расшифрование
std::string decryptMessage(const std::string& ciphertextB64) {
    try {
        std::vector<uint8_t> data = Botan::base64_decode(ciphertextB64);
        if (data.size() < 12) return "Некорректные данные";

        std::vector<uint8_t> nonce(data.begin(), data.begin() + 12);
        std::vector<uint8_t> cipher(data.begin() + 12, data.end());

        const std::string keyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        const std::vector<uint8_t> key = Botan::hex_decode(keyHex);

        auto dec = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        dec->set_key(key);
        dec->start(nonce);

        std::vector<uint8_t> pt(cipher.size());
        dec->finish(cipher, pt);

        return std::string(pt.begin(), pt.end());
    }
    catch (const std::exception& e) {
        return "Ошибка расшифрования: " + std::string(e.what());
    }
}

int main() {
    std::cout << "Бот запущен. Используется Botan " << Botan::version_string() << std::endl;

    long long lastUpdateId = 0;

    while (true) {
        std::string url = TELEGRAM_API + "getUpdates?offset=" + std::to_string(lastUpdateId + 1) + "&timeout=30";
        std::string response = httpGet(url);

        try {
            auto updates = json::parse(response);
            if (updates.contains("result") && updates["result"].is_array()) {
                for (auto& update : updates["result"]) {
                    long long updateId = update["update_id"];
                    if (updateId > lastUpdateId) lastUpdateId = updateId;

                    if (update.contains("message") && update["message"].contains("text")) {
                        std::string chatId = std::to_string(update["message"]["chat"]["id"].get<long long>());
                        std::string userText = update["message"]["text"];

                        if (userText == "/start") {
                            sendMessage(chatId, "🔐 Пришлите текст для шифрования или /decrypt <base64> для расшифровки");
                        }
                        else if (userText.rfind("/decrypt ", 0) == 0) {
                            std::string b64Data = userText.substr(9);
                            std::string decrypted = decryptMessage(b64Data);
                            sendMessage(chatId, "📖 Расшифровано: " + decrypted);
                        }
                        else {
                            std::string encrypted = encryptMessage(userText);
                            sendMessage(chatId, "🔒 Зашифровано (AES-256-GCM):\n`" + encrypted + "`\n\nОтправьте /decrypt " + encrypted + " для расшифровки");
                        }
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Ошибка: " << e.what() << std::endl;
        }

        sleep(1);
    }

    return 0;
}