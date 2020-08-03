#pragma once

#include "Serializable.h"
#include "IncomingMsgsStorage.hpp"

class KeyManager {
 public:
  struct KeyExchangeMsg : public concord::serialize::SerializableFactory<KeyExchangeMsg> {
    std::string key;
    std::string signature;
    int repID;
    KeyExchangeMsg(){};
    KeyExchangeMsg(std::string key, std::string signature, int repID);
    std::string toString() const;
    static KeyExchangeMsg deserializeMsg(const char* serStr, const int& size);

   protected:
    const std::string getVersion() const;
    void serializeDataMembers(std::ostream& outStream) const;
    void deserializeDataMembers(std::istream& inStream);
  };

 private:
  int repID_{};
  std::atomic_int counter_ = 0;
  std::string generateCid();
  IncomingMsgsStorage* msgQueue_{nullptr};

  KeyManager() {}
  KeyManager(const KeyManager&) = delete;
  KeyManager(const KeyManager&&) = delete;
  KeyManager& operator=(const KeyManager&) = delete;
  KeyManager& operator=(const KeyManager&&) = delete;

 public:
  std::atomic_bool keysExchanged{false};
  void setID(const int& id);
  void setMsgQueue(IncomingMsgsStorage* q);
  void sendKeyExchange();
  std::string onKeyExchange(const KeyExchangeMsg& kemsg);
  void onCheckpoint(const int& num);

  static KeyManager& get() {
    static KeyManager km;
    return km;
  }
};
