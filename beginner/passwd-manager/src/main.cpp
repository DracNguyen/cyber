// main.cpp
//
// Talks to: everything above (vault, crypto, generator, constants).
// Job: glue between the user's keyboard and the rest of the code. Knows
// nothing about cryptography -- it calls UnlockedVault::Create/Unlock and
// vault.Save(), and if we ever swap Argon2id for something else, this file
// does not change.
//
// This is a plain argv CLI (no third-party CLI framework, to keep the
// project dependency-free beyond OpenSSL + libargon2).

#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

#include "pv/constants.hpp"
#include "pv/exceptions.hpp"
#include "pv/generator.hpp"
#include "pv/vault.hpp"

namespace {

using pv::vault::Entry;
using pv::vault::UnlockedVault;

// ---------------------------------------------------------------------------
// Small terminal helpers (visible prompt / hidden password entry)
// ---------------------------------------------------------------------------

std::string PromptVisible(const std::string& label) {
  std::cout << label;
  std::cout.flush();
  std::string line;
  if (!std::getline(std::cin, line)) return "";
  return line;
}

// Equivalent of Python's getpass.getpass(): prints the prompt, disables
// terminal echo while reading, restores it afterward -- even if an
// exception unwinds through here.
std::string PromptHidden(const std::string& label) {
  std::cout << label;
  std::cout.flush();

  termios old_attrs{};
  bool have_tty = (::tcgetattr(STDIN_FILENO, &old_attrs) == 0);
  if (have_tty) {
    termios new_attrs = old_attrs;
    new_attrs.c_lflag &= ~ECHO;
    ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_attrs);
  }

  std::string line;
  bool ok = static_cast<bool>(std::getline(std::cin, line));

  if (have_tty) {
    ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_attrs);
    std::cout << "\n";
  }
  if (!ok) return "";
  return line;
}

std::string PromptNewMasterPassword(const std::string& label) {
  while (true) {
    std::string p1 = PromptHidden(label + ": ");
    std::string p2 = PromptHidden(label + " (confirm): ");
    if (p1 != p2) {
      std::cerr << "Passwords do not match, try again.\n";
      continue;
    }
    if (p1.size() < pv::constants::kMasterPasswordMinLen) {
      std::cerr << "Master password must be at least "
                << pv::constants::kMasterPasswordMinLen << " characters.\n";
      continue;
    }
    return p1;
  }
}

std::filesystem::path ResolveVaultPath(const std::string& vault_flag) {
  if (!vault_flag.empty()) return std::filesystem::path(vault_flag);
  if (const char* env = std::getenv("PV_VAULT_PATH")) {
    return std::filesystem::path(env);
  }
  return pv::vault::DefaultVaultPath();
}

// Very small argv option scanner: looks for `--name value` or `--flag`
// anywhere in args, removing them so positional args can be read after.
struct Args {
  std::vector<std::string> positional;
  std::map<std::string, std::string> options;
  std::set<std::string> flags;
};

Args ParseArgs(int argc, char** argv, int start,
                const std::set<std::string>& known_options,
                const std::set<std::string>& known_flags) {
  Args args;
  for (int i = start; i < argc; ++i) {
    std::string tok = argv[i];
    if (tok.rfind("--", 0) == 0) {
      std::string name = tok.substr(2);
      if (known_flags.count(name)) {
        args.flags.insert(name);
      } else if (known_options.count(name)) {
        if (i + 1 >= argc) {
          throw pv::ValidationError("Missing value for --" + name);
        }
        args.options[name] = argv[++i];
      } else {
        throw pv::ValidationError("Unknown option: --" + name);
      }
    } else {
      args.positional.push_back(tok);
    }
  }
  return args;
}

void PrintUsage() {
  std::cout <<
      "pv - a small local password manager\n\n"
      "Usage:\n"
      "  pv init                                  create a new vault\n"
      "  pv add <name> [--generate] [--length N] [--force]\n"
      "  pv get <name>\n"
      "  pv list\n"
      "  pv delete <name>\n"
      "  pv change-password\n"
      "  pv gen [length] [--no-lower] [--no-upper] [--no-digits] [--no-symbols]\n"
      "\n"
      "Global option:\n"
      "  --vault <path>   override the vault file location\n"
      "                   (default: ~/.password-vault/vault.json,\n"
      "                    or $PV_VAULT_PATH if set)\n";
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

int CmdInit(const std::filesystem::path& vault_path) {
  if (std::filesystem::exists(vault_path)) {
    std::cerr << "A vault already exists at " << vault_path << "\n";
    return 1;
  }
  std::string master = PromptNewMasterPassword("New master password");
  UnlockedVault v = UnlockedVault::Create(vault_path, master);
  std::cout << "Vault created at " << vault_path.string() << "\n";
  return 0;
}

int CmdAdd(const std::filesystem::path& vault_path, const Args& args) {
  if (args.positional.empty()) {
    std::cerr << "Usage: pv add <name> [--generate] [--length N] [--force]\n";
    return 1;
  }
  std::string name = args.positional[0];
  bool force = args.flags.count("force") != 0;
  bool generate = args.flags.count("generate") != 0;
  std::size_t length = pv::constants::kGeneratedPasswordDefaultLen;
  if (auto it = args.options.find("length"); it != args.options.end()) {
    length = static_cast<std::size_t>(std::stoul(it->second));
  }

  std::string master = PromptHidden("Master password: ");
  UnlockedVault v = UnlockedVault::Unlock(vault_path, master);

  Entry e;
  e.username = PromptVisible("Username: ");
  if (generate) {
    pv::generator::Options opts;
    opts.length = length;
    e.password = pv::generator::GeneratePassword(opts);
    std::cout << "Generated password: " << e.password << "\n";
  } else {
    e.password = PromptHidden("Password: ");
  }
  e.url = PromptVisible("URL (optional): ");
  e.notes = PromptVisible("Notes (optional): ");
  std::string now = pv::vault::NowIso8601Utc();
  e.created_at = now;
  e.updated_at = now;

  v.AddEntry(name, e, force);
  v.Save();
  std::cout << "Added entry: " << name << "\n";
  return 0;
}

int CmdGet(const std::filesystem::path& vault_path, const Args& args) {
  if (args.positional.empty()) {
    std::cerr << "Usage: pv get <name>\n";
    return 1;
  }
  std::string master = PromptHidden("Master password: ");
  UnlockedVault v = UnlockedVault::Unlock(vault_path, master);
  const Entry& e = v.GetEntry(args.positional[0]);

  std::cout << "----------------------------------------\n";
  std::cout << "name:     " << args.positional[0] << "\n";
  std::cout << "username: " << e.username << "\n";
  std::cout << "password: " << e.password << "\n";
  if (!e.url.empty()) std::cout << "url:      " << e.url << "\n";
  if (!e.notes.empty()) std::cout << "notes:    " << e.notes << "\n";
  std::cout << "updated:  " << e.updated_at << "\n";
  std::cout << "----------------------------------------\n";
  return 0;
}

int CmdList(const std::filesystem::path& vault_path) {
  std::string master = PromptHidden("Master password: ");
  UnlockedVault v = UnlockedVault::Unlock(vault_path, master);
  if (v.Empty()) {
    std::cout << "Vault is empty.\n";
    return 0;
  }
  // Deliberately does NOT print passwords -- see ARCHITECTURE.md section 6.
  std::printf("%-24s %-24s %s\n", "NAME", "USERNAME", "UPDATED_AT");
  for (const auto& name : v.Names()) {
    const Entry& e = v.GetEntry(name);
    std::printf("%-24s %-24s %s\n", name.c_str(), e.username.c_str(),
                e.updated_at.c_str());
  }
  return 0;
}

int CmdDelete(const std::filesystem::path& vault_path, const Args& args) {
  if (args.positional.empty()) {
    std::cerr << "Usage: pv delete <name>\n";
    return 1;
  }
  std::string master = PromptHidden("Master password: ");
  UnlockedVault v = UnlockedVault::Unlock(vault_path, master);
  v.DeleteEntry(args.positional[0]);
  v.Save();
  std::cout << "Deleted entry: " << args.positional[0] << "\n";
  return 0;
}

int CmdChangePassword(const std::filesystem::path& vault_path) {
  std::string current = PromptHidden("Current master password: ");
  UnlockedVault v = UnlockedVault::Unlock(vault_path, current);
  std::string new_password = PromptNewMasterPassword("New master password");
  v.ChangeMasterPassword(new_password);
  v.Save();
  std::cout << "Master password changed. Vault re-encrypted at "
            << vault_path.string() << "\n";
  return 0;
}

int CmdGen(const Args& args) {
  pv::generator::Options opts;
  if (!args.positional.empty()) {
    opts.length = static_cast<std::size_t>(std::stoul(args.positional[0]));
  }
  if (args.flags.count("no-lower")) opts.use_lowercase = false;
  if (args.flags.count("no-upper")) opts.use_uppercase = false;
  if (args.flags.count("no-digits")) opts.use_digits = false;
  if (args.flags.count("no-symbols")) opts.use_symbols = false;

  std::string pw = pv::generator::GeneratePassword(opts);
  // Plain printf/print, not iostream-with-formatting: this is the one
  // command meant to be piped (`pv gen 32 | pbcopy`), so no extra
  // decoration should ever end up in stdout.
  std::printf("%s\n", pw.c_str());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    PrintUsage();
    return 1;
  }
  std::string cmd = argv[1];

  if (cmd == "-h" || cmd == "--help" || cmd == "help") {
    PrintUsage();
    return 0;
  }

  try {
    if (cmd == "gen") {
      Args args = ParseArgs(argc, argv, 2, {},
                             {"no-lower", "no-upper", "no-digits", "no-symbols"});
      return CmdGen(args);
    }

    // Every other command needs a resolved vault path.
    Args args = ParseArgs(argc, argv, 2, {"vault", "length"},
                           {"generate", "force"});
    std::filesystem::path vault_path =
        ResolveVaultPath(args.options.count("vault") ? args.options["vault"] : "");

    if (cmd == "init") return CmdInit(vault_path);
    if (cmd == "add") return CmdAdd(vault_path, args);
    if (cmd == "get") return CmdGet(vault_path, args);
    if (cmd == "list") return CmdList(vault_path);
    if (cmd == "delete") return CmdDelete(vault_path, args);
    if (cmd == "change-password") return CmdChangePassword(vault_path);

    std::cerr << "Unknown command: " << cmd << "\n\n";
    PrintUsage();
    return 1;
  } catch (const pv::WrongPasswordError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const pv::VaultNotFoundError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const pv::VaultAlreadyExistsError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const pv::EntryNotFoundError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const pv::EntryAlreadyExistsError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const pv::InvalidVaultFormatError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const pv::ValidationError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const pv::PvError& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "Unexpected error: " << e.what() << "\n";
    return 1;
  }
}
