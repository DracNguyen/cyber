// json.hpp
//
// Talks to: nothing.
//
// A deliberately small JSON value type + parser + serializer. We don't need
// a general-purpose JSON library: the vault format only ever contains
// objects, strings, and integers (see ARCHITECTURE.md section 3). Writing
// ~150 lines here avoids pulling in a third-party dependency for a schema
// this narrow.
//
// Not meant for arbitrary JSON in the wild -- it intentionally rejects
// arrays, floats, booleans, and null, since the vault format never uses
// them. That rejection is a feature: an on-disk file using a construct we
// don't understand should fail loudly, not get silently coerced.

#pragma once

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>

namespace pv::json {

class ParseError : public std::runtime_error {
 public:
  explicit ParseError(const std::string& what) : std::runtime_error(what) {}
};

class Value {
 public:
  enum class Type { kNull, kInt, kString, kObject };

  Value() : type_(Type::kNull) {}
  explicit Value(std::int64_t v) : type_(Type::kInt), int_(v) {}
  explicit Value(const std::string& v) : type_(Type::kString), str_(v) {}
  explicit Value(const char* v) : type_(Type::kString), str_(v) {}

  static Value MakeObject() {
    Value v;
    v.type_ = Type::kObject;
    return v;
  }

  Type type() const { return type_; }
  bool is_object() const { return type_ == Type::kObject; }
  bool is_string() const { return type_ == Type::kString; }
  bool is_int() const { return type_ == Type::kInt; }

  // Object accessors ---------------------------------------------------
  Value& operator[](const std::string& key) {
    type_ = Type::kObject;
    return obj_[key];
  }
  const Value& at(const std::string& key) const {
    auto it = obj_.find(key);
    if (it == obj_.end()) {
      throw ParseError("missing required field: " + key);
    }
    return it->second;
  }
  bool contains(const std::string& key) const {
    return obj_.find(key) != obj_.end();
  }
  const std::map<std::string, Value>& items() const { return obj_; }

  // Scalar accessors ----------------------------------------------------
  const std::string& as_string() const {
    if (type_ != Type::kString) throw ParseError("expected a string field");
    return str_;
  }
  std::int64_t as_int() const {
    if (type_ != Type::kInt) throw ParseError("expected an integer field");
    return int_;
  }

  // Convenience: fetch + type-check + convert in one call.
  const std::string& get_string(const std::string& key) const {
    return at(key).as_string();
  }
  std::int64_t get_int(const std::string& key) const {
    return at(key).as_int();
  }

  std::string dump() const;

  static Value parse(const std::string& text);

 private:
  Type type_;
  std::int64_t int_ = 0;
  std::string str_;
  std::map<std::string, Value> obj_;
};

}  // namespace pv::json
