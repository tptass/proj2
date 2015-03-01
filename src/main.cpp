#include <memory>
#include <algorithm>
#include <string>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <deque>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#define DO_FORK

namespace fs = boost::filesystem;
namespace opts = boost::program_options;

/** Random message encryption key. */
static uint8_t msg_key = 0x06;

/**
 * Message flags.
 */
enum MsgFlag {
    MsgFlagNoop = 0,        // Do nothing.
    MsgFlagEcho = 1,        // Echo the message back.
    MsgFlagEncrypted = 2,   // Encrypted message (experimental).
};

/**
 * Message header.
 */
struct MsgHdr {
    uint16_t msg_flags_;
    uint16_t msg_len_;
} __attribute__((packed));

/**
 * Configuration.
 */
struct Config {
    uint16_t port_ = 12000;
    uint32_t secret_ = 0u;
};

/**
 * Exception.
 */
class Exception : public std::exception {
public:
    /**
     * Constructor.
     *
     * @param msg Message.
     */
    explicit Exception(const std::string& msg) : msg_(msg) {
    }

    virtual const char* what(void) const noexcept {
        return msg_.c_str();
    }

private:
    const std::string msg_;
};

/**
 * Exit with an error message.
 *
 * @param desc Options.
 * @param msg Message.
 */
static void ExitError(opts::options_description& desc, const std::string msg) {
    std::cout << desc << "\nERROR: " << msg << ".\n";
    exit(1);
}

/**
 * Parse arguments.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param[out] conf Configuration.
 */
static void ParseArgs(int argc, char** argv, Config& conf) {
    std::stringstream usage;
    usage << "Usage: " PROJECT_NAME " <command> [options]";
    opts::options_description visible_desc(usage.str());

    try {
        opts::options_description common_desc("# Common options");
        common_desc.add_options()
            ("config", opts::value<std::string>(), "Path to configuration file.")
            ("help", "Print this usage information.")
            ("port", opts::value<uint16_t>(), "Port.")
            ("secret", opts::value<uint32_t>(), "Secret.")
            ;

        visible_desc.add(common_desc);

        opts::variables_map vm;
        opts::store(
            opts::command_line_parser(argc, argv)
                .options(visible_desc)
                .run(),
            vm);

        if (vm.count("config")) {
            fs::path path(vm["config"].as<std::string>());
            if (!fs::exists(path))
                ExitError(visible_desc, "configuration file does not exist");

            try {
                opts::store(opts::parse_config_file<char>(path.c_str(), visible_desc), vm);
            } catch (const std::exception& e) {
                ExitError(visible_desc, "unable to parse configuration file");
            }
        }

        opts::notify(vm);

        if (vm.count("secret")) {
            conf.secret_ = vm["secret"].as<uint32_t>();
        }

        if (vm.count("port")) {
            conf.port_ = vm["port"].as<uint16_t>();
        }

        if (vm.count("help")) {
            std::cout << visible_desc;
            exit(0);
        }

    } catch (const std::exception& e) {
        std::stringstream msg;
        msg << "unable to process options -- " << e.what();
        ExitError(visible_desc, msg.str());
    }
}

/**
 * Set a read timeout.
 *
 * @param sk Socket.
 * @return True if successful.
 */
static bool SetReadTimeout(const int sk) {
    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
      std::cerr << "unable to set read timeout";
      return false;
    }

    return true;
}

/**
 * Read n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to read.
 * @return True if successful.
 */
static bool ReadBytes(const int sk, char* buf, const size_t n) {
    char* ptr = buf;
    while (ptr < buf + n) {
        if (!SetReadTimeout(sk)) {
            return false;
        }

        auto ret = recv(sk, ptr, ptr - buf + n, 0);
        if (ret <= 0) {
	  //LOG(ERROR) << "unable to receive on socket";
            return false;
        }

        ptr += ret;
    }

    return true;
}

/**
 * Write n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to write.
 * @return True if successful.
 */
static bool WriteBytes(const int sk, const char* buf, const size_t n) {
    auto ptr = buf;
    while (ptr < buf + n) {
        auto ret = send(sk, ptr, n - (ptr - buf), 0);
        if (ret <= 0) {
	  std::cerr << "unable to send on socket";
	  return false;
        }

        ptr += ret;
    }

    return true;
}

/**
 * Decrypt a buffer.
 *
 * @param key Key.
 * @param buf Buffer.
 * @param n Number of bytes to decrypt.
 */
static void DecryptBuf(const uint8_t key, char* buf, const size_t n) {
    for (auto ptr = buf; ptr < buf + n; ++ptr) {
        *ptr = *ptr ^ key;
    }
}

/**
 * Handle a client.
 *
 * @param secret Secret value.
 * @param sk Socket.
 */
static void OnClient(uint32_t secret, const int sk) {
    volatile uint32_t cookie = secret;

    char buf[1024];
    MsgHdr hdr;

    if (!ReadBytes(sk, reinterpret_cast<char*>(&hdr), sizeof(hdr))) {
      std::cerr << "unable to read message header";
      return;
    }

    if (hdr.msg_flags_ & MsgFlagEcho) {
        if (hdr.msg_len_ > sizeof(buf)) {
	  std::cerr << "ANOTHER OVERFLOW ATTEMPT, NICE TRY";
	  return;
        }

        if (hdr.msg_flags_ & MsgFlagEncrypted) {
            DecryptBuf(msg_key, reinterpret_cast<char*>(&hdr), sizeof(hdr));
        }

	std::cerr << "reading " << std::hex << hdr.msg_len_ << " bytes";

        if (!ReadBytes(sk, buf, hdr.msg_len_)) {
	  std::cerr << "unable to read message";
        }

        if (hdr.msg_flags_ & MsgFlagEncrypted) {
            DecryptBuf(msg_key, buf, hdr.msg_len_);
        }

        WriteBytes(sk, buf, hdr.msg_len_);
    }

    if (cookie != secret) {
      std::cerr << "ATTACK DETECTED, ABORTING";
      exit(0);
    }
}

/**
 * Run the service.
 *
 * @param conf Configuration.
 */
static void RunService(Config& conf) {
    auto sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0) {
      std::cerr << "unable to create server socket";
      std::cerr << strerror(errno);
      return;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(conf.port_);
    addr.sin_addr.s_addr = INADDR_ANY;

    auto opt = 1;
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
      std::cerr << "unable to set REUSE_ADDR on server socket";
      std::cerr << strerror(errno);
      return;
    }

    if (bind(sk, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      std::cerr << "unable to bind server socket";
      std::cerr << strerror(errno);
      return;
    }

    if (listen(sk, 16) < 0) {
      std::cerr << "unable to listen on server socket";
      std::cerr << strerror(errno);
      return;
    }

    while (true) {
        sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        memset(&client_addr, 0, sizeof(client_addr));
        auto client_sk =
            accept(
                sk,
                reinterpret_cast<sockaddr*>(&client_addr),
                &addr_len);
        if (client_sk < 0) {
	  std::cerr << "unable to accept connection";
	  std::cerr << strerror(errno);
	  return;
        }

#ifdef DO_FORK
        pid_t child;
        switch (child = fork()) {
            case -1:
	      std::cerr << "unable to fork client handler";
	      std::cerr << strerror(errno);
	      return;

            case 0:
#endif // DO_FORK
                if (!conf.secret_) {
                    conf.secret_ = random();
                }

                OnClient(conf.secret_, client_sk);
#ifdef DO_FORK
                exit(0);

            default:
#endif // DO_FORK
                close(client_sk);
#ifdef DO_FORK
                break;
        }

        while (true) {
            int st;
            if (waitpid(-1, &st, WNOHANG) < 0) {
                break;
            }
        }
#endif // DO_FORK
    }
}

/**
 * Main.
 */
int main(int argc, char** argv) {
    Config conf;
    ParseArgs(argc, argv, conf);
    RunService(conf);
    return 0;
}
