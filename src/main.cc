#include "utils.h"
#include "prop.h"

// 未来可能需要更新？但是ksu好像并没有改变过这些，所以硬编码了
#define FILE_MAGIC 0x7f4b5355 // ' KSU', u32
#define FILE_FORMAT_VERSION 3 // u32
#define KSU_MAX_PACKAGE_NAME 256

struct RootProfile {
    int32_t uid;
    int32_t gid;
    int32_t groups_count;
    int32_t groups[32];
    struct {
        uint64_t effective;
        uint64_t permitted;
        uint64_t inheritable;
    } capabilities;
    char selinux_domain[64];
    int32_t namespaces;
};

struct NonRootProfile {
    bool umount_modules;
};

struct AppProfile {
    uint32_t version;
    char key[KSU_MAX_PACKAGE_NAME];
    int32_t current_uid;
    bool allow_su;
    union {
        struct {
            bool use_default;
            char template_name[KSU_MAX_PACKAGE_NAME];
            RootProfile profile;
        } rp_config;
        struct {
            bool use_default;
            NonRootProfile profile;
        } nrp_config;
    };
};

std::vector<AppProfile> allow_list;
bool default_umount = false;

// 在这里读取.allowlist文件
void LoadAllowList(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        exit(1);
    }

    uint32_t magic, version;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.read(reinterpret_cast<char*>(&version), sizeof(version));

    if (magic != FILE_MAGIC || version != FILE_FORMAT_VERSION) {
        std::cerr << "Invalid file format" << std::endl;
        exit(2);
    }

    while (file) {
        AppProfile profile;
        file.read(reinterpret_cast<char*>(&profile), sizeof(profile));

        if (file) {
            allow_list.push_back(profile);
        }
    }

    std::cout << "Loaded " << allow_list.size() << " profiles from allowlist." << std::endl;
}

// 在这里检查是否默认umount，通过读取配置文件config.txt实现
void LoadConfig(const std::string &filename) {
    int value = readInt(filename.c_str());
    default_umount = (value == 1);
}

// 在这里检查包名
bool CheckPackage(const std::string &package) {
    // ksu管理器本身是不umount的
    if (package == "me.weishu.kernelsu") {
        return false;
    }

    for (const auto &profile : allow_list) {
        if (std::strcmp(profile.key, package.c_str()) == 0) {
            if (profile.allow_su) {
                return false;
            } else if (profile.nrp_config.profile.umount_modules) {
                return true;
            } else if (profile.nrp_config.use_default) {
                return default_umount;
            } else {
                return false;
            }
        }
    }
    return default_umount;
}

int main(int argc, char** argv) {
    // 可执行文件和模块属性文件在同一目录
    Prop moduleProp(parentDir(string(argv[0])) + "/module.prop");

    // 这里读取的.allowlist(应该)是只有KSU有的
    std::string allowlist_path = "/data/adb/ksu/.allowlist";
    std::string config_path = parentDir(string(argv[0])) + "/default_umount.txt";
    std::string dump_path = "/data/adb/tricky_store/target.txt"; // 这算不算一种僭越呢？(笑)

    LoadAllowList(allowlist_path);
    LoadConfig(config_path);

    // 获取 target.txt 的行数
    int origin = countLines(dump_path);

    FILE *fp = popen("pm list packages", "r"); // 执行pm list packages命令，用于获取所有已安装的应用，如果要排除系统应用，加上 “-3”, 但是在大多数rom中gms是系统应用，所以不排除
    if (fp == NULL) {
        std::cerr << "Failed to run pm list packages" << std::endl;
        return 5;
    }

    std::ofstream dump_file(dump_path);
    if (!dump_file) {
        std::cerr << "Failed to open dump file: " << dump_path << std::endl;
        return 6;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        std::string package(line);
        package = package.substr(8); // 删除前缀 "package:"
        package.erase(package.find_last_not_of(" \n\r\t") + 1); // 去除尾部的空白字符

        bool result = CheckPackage(package);
        if (result) {
            dump_file << package << std::endl; // 在这里将所有需要umount的应用包名写入target.txt
        }
    }

    pclose(fp);
    dump_file.close();

    // 获取刷新后 target.txt 的行数
    int count = countLines(dump_path);

    // 更新描述
    std::string new_description;
    if (count == 0) {
        new_description = "[😥0 app umounted?]";
    } else {
        new_description = "[😋" + std::to_string(count) + " apps in list. Added " + std::to_string(count - origin) + " apps.] いいこと？暁の水平線に勝利を刻みなさいっ！";
    }
    moduleProp["description"] = new_description;
    moduleProp.save2file(); // 保存到 module.prop

    return 0;
}