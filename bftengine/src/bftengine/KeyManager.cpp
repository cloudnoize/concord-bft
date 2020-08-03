#include "KeyManager.h"
#include "thread"
#include "ReplicaImp.hpp"
#include "ReplicaConfig.hpp"
#include <memory>
#include "messages/ClientRequestMsg.hpp"

const std::string KeyManager::KeyExchangeMsg::getVersion() const { return "1"; }

KeyManager::KeyExchangeMsg::KeyExchangeMsg(std::string k, std::string s, int id)
    : key(std::move(k)), signature(std::move(s)), repID(id) {}

KeyManager::KeyExchangeMsg KeyManager::KeyExchangeMsg::deserializeMsg(const char* serializedMsg, const int& size) {
  std::stringstream ss;
  KeyManager::KeyExchangeMsg ke;
  ss.write(serializedMsg, std::streamsize(size));
  deserialize(ss, ke);
  return ke;
}

void KeyManager::KeyExchangeMsg::serializeDataMembers(std::ostream& outStream) const {
  serialize(outStream, key);
  LOG_TRACE(GL, "KEY EXCHANGE MANAGER  ser  key_ " << key);
  serialize(outStream, signature);
  LOG_TRACE(GL, "KEY EXCHANGE MANAGER  ser  signature_ " << signature);
  serialize(outStream, repID);
  LOG_TRACE(GL, "KEY EXCHANGE MANAGER  ser  repID_ " << repID);
}

void KeyManager::KeyExchangeMsg::deserializeDataMembers(std::istream& inStream) {
  deserialize(inStream, key);
  deserialize(inStream, signature);
  deserialize(inStream, repID);
}

std::string KeyManager::KeyExchangeMsg::toString() const {
  std::stringstream ss;
  ss << "key [" << key << "] signature [" << signature << "] replica id [" << repID << "]";
  return ss.str();
}

void KeyManager::setID(const int& id) { repID_ = id; }

void KeyManager::setMsgQueue(IncomingMsgsStorage* q) { msgQueue_ = q; }

/*
Usage:
  KeyExchangeMsg msg{key,sig,id};
  std::stringstream ss;
  concord::serialize::Serializable::serialize(ss, msg);
  auto strMsg = ss.str();
  char buff[128];
  uint32_t actSize{};
  // magic numbers, need to check valid values.
  cl_->invokeCommandSynch(strMsg.c_str(),
                          strMsg.size(),
                          bftEngine::KEY_EXCHANGE_FLAG,
                          std::chrono::milliseconds(60000),
                          44100,
                          buff,
                          &actSize);
*/
void KeyManager::sendKeyExchange() {
  counter_++;
  KeyExchangeMsg msg{"3c9dac7b594efaea8acd66a18f957f2e", "82c0700a4b907e189529fcc467fd8a1b", repID_};
  std::stringstream ss;
  concord::serialize::Serializable::serialize(ss, msg);
  auto strMsg = ss.str();
  auto crm = new ClientRequestMsg(
      repID_ + 10000, bftEngine::KEY_EXCHANGE_FLAG, counter_, strMsg.size(), strMsg.c_str(), 60000, generateCid());
  msgQueue_->pushExternalMsg(std::unique_ptr<MessageBase>(crm));
  LOG_DEBUG(GL, "KEY EXCHANGE MANAGER  send msg");
}

std::string KeyManager::generateCid() {
  std::string cid{"KEY-EXCHANGE-"};
  cid += std::to_string(repID_) + "-" + std::to_string(counter_);
  return cid;
}

std::string KeyManager::onKeyExchange(const KeyExchangeMsg& kemsg) {
  counter_++;
  LOG_DEBUG(GL, "KEY EXCHANGE MANAGER  msg " << kemsg.toString());
  auto numRep = bftEngine::ReplicaConfigSingleton::GetInstance().GetNumReplicas();
  if (counter_ < numRep) {
    LOG_DEBUG(GL, "Exchanged [" << counter_ << "] out of [" << numRep << "]");
  } else if (counter_ == numRep) {
    LOG_INFO(GL, "KEY EXCHANGE: start accepting msgs");
    keysExchanged = true;
  }
  return "ok";
}

void KeyManager::onCheckpoint(const int& num) { LOG_DEBUG(GL, "KEY EXCHANGE MANAGER check point  " << num); }
