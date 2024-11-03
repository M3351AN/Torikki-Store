#include "prop.h"
#include "utils.h"

namespace fs = std::filesystem;

// 全局变量存储吊销列表
std::vector<std::string> crl_entries;

// 执行系统命令并获取输出
std::string ExecCommand(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// 获取吊销列表
bool GetCrl() {
    std::string cmd = "curl -X GET 'https://android.googleapis.com/attestation/status'";
    std::string json_response = ExecCommand(cmd);

    // 使用正则表达式查找吊销的序列号
    std::regex re("\"([^\"]+)\"\\s*:\\s*\\{\\s*\"status\"\\s*:\\s*\"REVOKED\"");
    std::smatch match;
    std::string::const_iterator searchStart(json_response.cbegin());
    while (std::regex_search(searchStart, json_response.cend(), match, re)) {
        crl_entries.push_back(match.str(1));
        searchStart = match.suffix().first;
    }

    if (crl_entries.empty()) {
        std::cout << "! Error: No revoked certificates found" << std::endl;
        return false;
    }

    // 保存吊销列表到本地文件
    std::ofstream crl_cache("crl_cache.txt");
    for (const auto& entry : crl_entries) {
        crl_cache << entry << std::endl;
    }
    crl_cache.close();

    return true;
}

// 从本地缓存加载吊销列表
void LoadCrlFromCache() {
    std::ifstream file("crl_cache.txt");
    if (!file.is_open()) {
        std::cout << "! Error: Unable to open crl_cache.txt" << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        crl_entries.push_back(line);
    }
    file.close();
}

// 解析证书并返回序列号
std::string ParseCert(const std::string& cert_str) {
    std::string cmd = "curl -X POST 'https://myssl.com/api/v1/tools/cert_decode' "
                      "-H 'User-Agent: Sukaaretto' "
                      "-F 'cert=" + cert_str + "' "
                      "-F 'type=paste'";

    std::string json_response = ExecCommand(cmd);

    // 使用正则表达式查找序列号
    std::regex re_sn("\"sn\":\"([^\"]+)\"");
    std::smatch match;
    if (std::regex_search(json_response, match, re_sn) && match.size() > 1) {
        return match.str(1);
    } else {
        std::cout << "! Error: Serial number not found" << std::endl;
        return "";
    }
}

// 手动解析 XML 文件并获取证书内容
std::vector<std::string> ParseXML(const std::string& xml_file) {
    std::ifstream file(xml_file);
    if (!file.is_open()) {
        std::cout << "! Error: Unable to open file " << xml_file << std::endl;
        return {};
    }

    std::vector<std::string> certs;
    std::string line;
    std::string cert;
    bool in_cert = false;

    while (std::getline(file, line)) {
        if (line.find("<Certificate") != std::string::npos) {
            in_cert = true;
            cert.clear();
        } else if (line.find("</Certificate>") != std::string::npos) {
            in_cert = false;
            certs.push_back(cert);
        } else if (in_cert) {
            cert += line + "\n";
        }
    }

    file.close();
    return certs;
}
bool is_aosp;
// 检查证书是否被吊销
bool CheckIfRevoked(const std::string& xml_file) {
    std::ifstream file(xml_file);
    if (!file.is_open()) {
        std::cout << "! Error: Unable to open file " << xml_file << std::endl;
        return true;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("<Keybox DeviceID=\"sw\">") != std::string::npos) {
            std::cout << "- Keybox is signed with AOSP cert!" << std::endl;
            is_aosp = true;
            return false;
        }
    }

    file.close();

    std::vector<std::string> certs = ParseXML(xml_file);

    if (certs.empty()) {
        std::cout << "! Error: No certificates found in " << xml_file << ". Skipping..." << std::endl;
        return false;
    }

    std::string ec_cert_sn = ParseCert(certs[0]);
    std::string rsa_cert_sn = ParseCert(certs[3]);

    std::cout << "EC Cert SN: " << ec_cert_sn << std::endl;
    std::cout << "RSA Cert SN: " << rsa_cert_sn << std::endl;

    if (std::find(crl_entries.begin(), crl_entries.end(), ec_cert_sn) != crl_entries.end() ||
        std::find(crl_entries.begin(), crl_entries.end(), rsa_cert_sn) != crl_entries.end()) {
        std::cout << "- Certificate is revoked." << std::endl;
        return true;
    }

    return false;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <xml_file>" << std::endl;
        return 1;
    }

    // 可执行文件和模块属性文件在同一目录
    Prop module_prop(parentDir(std::string(argv[0])) + "/module.prop");

    bool crl_fetched = GetCrl();
    if (!crl_fetched) {
        LoadCrlFromCache();
    }

    std::string xml_file = argv[1];
    bool is_revoked = CheckIfRevoked(xml_file);
    std::string origin_description = module_prop["info"];
    // 更新描述
    std::string new_description;
    if (is_revoked) {
        new_description = "[😥Keybox cert revoked!]" + origin_description;
        std::cout << "! Keybox cert revoked!" << std::endl;
    } else if (is_aosp) {
        new_description = "[🤤Keybox signed with AOSP cert!]" + origin_description;
        std::cout << "- Keybox signed with AOSP cert!" << std::endl;
    } else if (!crl_fetched) {
        new_description = "[😉Plz fetch CRL with stable network connection!]" + origin_description;
        std::cout << "! Plz fetch CRL with stable network connection!" << std::endl;
    } else {
        new_description = "[😋Keybox valid!]" + origin_description;
        std::cout << "- Keybox valid!" << std::endl;
    }
    module_prop["description"] = new_description;
    module_prop.save2file(); // 保存到 module.prop
    return 0;
}