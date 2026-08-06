#include "pv/json.hpp"

#include <cctype>
#include <sstream>

namespace pv::json {

namespace {

class Parser {
 public:
  explicit Parser(const std::string& text) : text_(text) {}

  Value ParseValue() {
    SkipWs();
    if (pos_ >= text_.size()) throw ParseError("unexpected end of input");
    char c = text_[pos_];
    if (c == '{') return ParseObject();
    if (c == '"') return Value(ParseString());
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
      return ParseInt();
    }
    throw ParseError("unexpected character while parsing JSON value");
  }

  void ExpectEnd() {
    SkipWs();
    if (pos_ != text_.size()) {
      throw ParseError("trailing data after JSON value");
    }
  }

 private:
  const std::string& text_;
  std::size_t pos_ = 0;

  void SkipWs() {
    while (pos_ < text_.size() &&
           std::isspace(static_cast<unsigned char>(text_[pos_]))) {
      ++pos_;
    }
  }

  char Peek() {
    if (pos_ >= text_.size()) throw ParseError("unexpected end of input");
    return text_[pos_];
  }

  char Advance() {
    if (pos_ >= text_.size()) throw ParseError("unexpected end of input");
    return text_[pos_++];
  }

  void Expect(char c) {
    if (Advance() != c) {
      throw ParseError(std::string("expected '") + c + "'");
    }
  }

  Value ParseObject() {
    Expect('{');
    Value obj = Value::MakeObject();
    SkipWs();
    if (Peek() == '}') {
      Advance();
      return obj;
    }
    while (true) {
      SkipWs();
      std::string key = ParseString();
      SkipWs();
      Expect(':');
      SkipWs();
      obj[key] = ParseValue();
      SkipWs();
      char c = Advance();
      if (c == ',') continue;
      if (c == '}') break;
      throw ParseError("expected ',' or '}' in object");
    }
    return obj;
  }

  std::string ParseString() {
    Expect('"');
    std::string out;
    while (true) {
      char c = Advance();
      if (c == '"') break;
      if (c == '\\') {
        char esc = Advance();
        switch (esc) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'n': out.push_back('\n'); break;
          case 't': out.push_back('\t'); break;
          case 'r': out.push_back('\r'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'u': {
            // Minimal \uXXXX support: only handles the Basic Latin /
            // Latin-1 range, which covers everything our own writer
            // ever emits. Vault field values in this project are
            // ASCII by construction; this is enough to not crash on
            // hand-edited files using simple escapes.
            unsigned int code = 0;
            for (int i = 0; i < 4; ++i) {
              char h = Advance();
              code <<= 4;
              if (h >= '0' && h <= '9') code |= (h - '0');
              else if (h >= 'a' && h <= 'f') code |= (h - 'a' + 10);
              else if (h >= 'A' && h <= 'F') code |= (h - 'A' + 10);
              else throw ParseError("invalid \\u escape");
            }
            if (code < 0x80) {
              out.push_back(static_cast<char>(code));
            } else {
              // Encode as UTF-8 (2-byte range is enough for our use).
              out.push_back(static_cast<char>(0xC0 | (code >> 6)));
              out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
            break;
          }
          default:
            throw ParseError("invalid escape sequence");
        }
      } else {
        out.push_back(c);
      }
    }
    return out;
  }

  Value ParseInt() {
    std::size_t start = pos_;
    if (Peek() == '-') Advance();
    if (!std::isdigit(static_cast<unsigned char>(Peek()))) {
      throw ParseError("invalid number");
    }
    while (pos_ < text_.size() &&
           std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
      ++pos_;
    }
    // Reject floats explicitly: our schema never uses them, and silently
    // truncating one would hide a corrupted/foreign file.
    if (pos_ < text_.size() && (text_[pos_] == '.' || text_[pos_] == 'e' ||
                                 text_[pos_] == 'E')) {
      throw ParseError("floating point numbers are not supported");
    }
    return Value(static_cast<std::int64_t>(
        std::stoll(text_.substr(start, pos_ - start))));
  }
};

void EscapeInto(std::ostringstream& os, const std::string& s) {
  os << '"';
  for (char c : s) {
    switch (c) {
      case '"': os << "\\\""; break;
      case '\\': os << "\\\\"; break;
      case '\n': os << "\\n"; break;
      case '\t': os << "\\t"; break;
      case '\r': os << "\\r"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          os << buf;
        } else {
          os << c;
        }
    }
  }
  os << '"';
}

void DumpInto(std::ostringstream& os, const Value& v) {
  switch (v.type()) {
    case Value::Type::kString:
      EscapeInto(os, v.as_string());
      return;
    case Value::Type::kInt:
      os << v.as_int();
      return;
    case Value::Type::kObject: {
      os << '{';
      bool first = true;
      for (const auto& [key, val] : v.items()) {
        if (!first) os << ',';
        first = false;
        EscapeInto(os, key);
        os << ':';
        DumpInto(os, val);
      }
      os << '}';
      return;
    }
    case Value::Type::kNull:
      os << "null";
      return;
  }
}

}  // namespace

Value Value::parse(const std::string& text) {
  Parser p(text);
  Value v = p.ParseValue();
  p.ExpectEnd();
  return v;
}

std::string Value::dump() const {
  std::ostringstream os;
  DumpInto(os, *this);
  return os.str();
}

}  // namespace pv::json
