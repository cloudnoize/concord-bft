// Concord
//
// Copyright (c) 2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License"). You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the sub-component's license, as noted in the LICENSE
// file.

#include "KeyManager.h"
#include "thread"
#include "ReplicaConfig.hpp"
#include <memory>
#include "messages/ClientRequestMsg.hpp"

////////////////////////////// KEY MANAGER//////////////////////////////
namespace bftEngine::impl {
KeyManager::KeyManager(IinternalBFTClient* cl,
                       const int& id,
                       const uint32_t& clusterSize,
                       IReservedPages* reservedPages,
                       const uint32_t sizeOfReservedPage,
                       IPathDetector* pathDetect,
                       IKeyGenerator* kg,
                       std::shared_ptr<ISaverLoader>* sl,
                       concordUtil::Timers& timers)
    : repID_(id),
      clusterSize_(clusterSize),
      client_(cl),
      keyStore_{clusterSize, *reservedPages, sizeOfReservedPage},
      pathDetector_(pathDetect),
      keygen_(kg),
      timers_(timers) {
  if (sl) {
    prvKeys_.sl = *sl;
  }
  prvKeys_.load();
  if (keyStore_.exchangedReplicas.size() == clusterSize_) {
    // it's possible that all keys were exchanged but this replica crashed before the rotation.
    // So it has an outstandingPrivateKey.
    if (prvKeys_.privateKey.empty()) {
      prvKeys_.rotate(prvKeys_.privateKey, prvKeys_.outstandingPrivateKey);
      prvKeys_.save();
      ConcordAssert(prvKeys_.privateKey.empty() == false);
    }
    LOG_DEBUG(KEY_EX_LOG, "TODO build crypto system ");
    keysExchanged = true;
    LOG_INFO(KEY_EX_LOG, "All replicas keys loaded from reserved pages, can start accepting msgs");
  }
  // update keyexchange on start metric
  for (uint16_t i = 0; i < keyStore_.exchangedReplicas.size(); ++i) {
    metrics_->keyExchangedOnStartCounter.Get().Inc();
  }
}

void KeyManager::initMetrics(std::shared_ptr<concordMetrics::Aggregator> a, std::chrono::seconds interval) {
  metrics_.reset(new Metrics(a, interval));
  metrics_->component.Register();
  metricsTimer_ = timers_.add(std::chrono::milliseconds(100), Timers::Timer::RECURRING, [this](Timers::Handle h) {
    metrics_->component.UpdateAggregator();
    auto currTime =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch());
    if (currTime - metrics_->lastMetricsDumpTime >= metrics_->metricsDumpIntervalInSec) {
      metrics_->lastMetricsDumpTime = currTime;
      LOG_INFO(KEY_EX_LOG, "-- KeyManager metrics dump--" + metrics_->component.ToJson());
    }
  });
}

std::string KeyManager::generateCid() {
  std::string cid{"KEY-EXCHANGE-"};
  auto now = getMonotonicTime().time_since_epoch();
  auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now);
  auto sn = now_ms.count();
  cid += std::to_string(repID_) + "-" + std::to_string(sn);
  return cid;
}

std::string KeyManager::onKeyExchange(KeyExchangeMsg& kemsg, const uint64_t& sn) {
  LOG_DEBUG(KEY_EX_LOG, "Recieved " << kemsg.toString() << " seq num " << sn);
  if (!keysExchanged) {
    onInitialKeyExchange(kemsg, sn);
    return "ok";
  }
  if (kemsg.repID == repID_) {
    prvKeys_.rotate(prvKeys_.outstandingPrivateKey, prvKeys_.publishPrivateKey);
    prvKeys_.save();
  }
  if (keyStore_.push(kemsg, sn, registryToExchange_)) metrics_->keyExchangedCounter.Get().Inc();

  return "ok";
}

void KeyManager::onInitialKeyExchange(KeyExchangeMsg& kemsg, const uint64_t& sn) {
  // For some reason we recieved a key for a replica that already exchanged it's key.
  if (keyStore_.exchangedReplicas.find(kemsg.repID) != keyStore_.exchangedReplicas.end()) {
    LOG_WARN(KEY_EX_LOG, "Replica [" << kemsg.repID << "] already exchanged initial key");
    return;
  }
  // If replica id is not in set, check that it arrived in fast path in order to ensure n out of n.
  // If arrived in slow path do not insert to data structure and if repID == this.repID re-send keyexchange.
  // If arrived in fast path set private key to oustanding.
  if (pathDetector_->isSlowPath(sn)) {
    LOG_INFO(KEY_EX_LOG,
             "Initial key exchanged for replica ["
                 << kemsg.repID << "] is dropped, Consensus reached without n out of n participation");
    if (kemsg.repID == repID_) {
      LOG_INFO(KEY_EX_LOG, "Resending initial key exchange");
      sendKeyExchange();
    }
    return;
  }

  if (kemsg.repID == repID_) {
    prvKeys_.rotate(prvKeys_.outstandingPrivateKey, prvKeys_.publishPrivateKey);
    prvKeys_.save();
  }

  std::vector<IKeyExchanger*> registryToExchange;
  keyStore_.push(kemsg, sn, registryToExchange);
  keyStore_.exchangedReplicas.insert(kemsg.repID);
  metrics_->keyExchangedOnStartCounter.Get().Inc();
  LOG_DEBUG(KEY_EX_LOG, "Exchanged [" << keyStore_.exchangedReplicas.size() << "] out of [" << clusterSize_ << "]");
  if (keyStore_.exchangedReplicas.size() == clusterSize_) {
    prvKeys_.rotate(prvKeys_.privateKey, prvKeys_.outstandingPrivateKey);
    prvKeys_.save();
    LOG_DEBUG(KEY_EX_LOG, "TODO build crypto system ");
    keysExchanged = true;
    LOG_INFO(KEY_EX_LOG, "All replics exchanged keys, can start accepting msgs");
  }
}

void KeyManager::onCheckpoint(const int& num) {
  auto rotatedReplicas = keyStore_.rotate(num, registryToExchange_);
  if (rotatedReplicas.empty()) return;
  for (auto id : rotatedReplicas) {
    metrics_->publicKeyRotated.Get().Inc();
    if (id != repID_) continue;
    LOG_INFO(KEY_EX_LOG, "Rotating private key");
    prvKeys_.rotate(prvKeys_.privateKey, prvKeys_.outstandingPrivateKey);
    prvKeys_.save();
  }
  LOG_DEBUG(KEY_EX_LOG, "Check point  " << num << " trigerred rotation ");
  LOG_DEBUG(KEY_EX_LOG, "TODO build crypto system ");
}

void KeyManager::registerForNotification(IKeyExchanger* ke) { registryToExchange_.push_back(ke); }

KeyExchangeMsg KeyManager::getReplicaKey(const uint16_t& repID) const { return keyStore_.getReplicaKey(repID); }

void KeyManager::loadKeysFromReservedPages() { keyStore_.loadAllReplicasKeyStoresFromReservedPages(); }

/*
Usage:
  KeyExchangeMsg msg{"3c9dac7b594efaea8acd66a18f957f2e", "82c0700a4b907e189529fcc467fd8a1b", repID_};
  std::stringstream ss;
  concord::serialize::Serializable::serialize(ss, msg);
  auto strMsg = ss.str();
  client_->sendRquest(bftEngine::KEY_EXCHANGE_FLAG, strMsg.size(), strMsg.c_str(), generateCid());
*/

void KeyManager::sendKeyExchange() {
  KeyExchangeMsg msg;
  // Generate
  // TODO replace with real methods
  prvKeys_.publishPrivateKey = keygen_->getPrivateKey();
  prvKeys_.save();
  msg.key = keygen_->getPublicKey();
  msg.repID = repID_;
  std::stringstream ss;
  concord::serialize::Serializable::serialize(ss, msg);
  auto strMsg = ss.str();
  client_->sendRquest(bftEngine::KEY_EXCHANGE_FLAG, strMsg.size(), strMsg.c_str(), generateCid());
  LOG_DEBUG(KEY_EX_LOG, "Sending key exchange msg");
}

void KeyManager::sendInitialKey() {
  if (keyStore_.exchangedReplicas.find(repID_) != keyStore_.exchangedReplicas.end()) return;
  LOG_DEBUG(KEY_EX_LOG, "Didn't find replica's first generated keys, sending");
  sendKeyExchange();
}

/////////////PRIVATE KEYS////////////////////////////
void KeyManager::PrivateKeys::rotate(std::string& dst, std::string& src) {
  ConcordAssert(src.empty() == false);
  dst = src;
  src.clear();
}

const std::string KeyManager::PrivateKeys::getVersion() const { return "1"; }

void KeyManager::PrivateKeys::serializeDataMembers(std::ostream& outStream) const {
  serialize(outStream, privateKey);
  serialize(outStream, outstandingPrivateKey);
  serialize(outStream, publishPrivateKey);
}

void KeyManager::PrivateKeys::deserializeDataMembers(std::istream& inStream) {
  deserialize(inStream, privateKey);
  deserialize(inStream, outstandingPrivateKey);
  deserialize(inStream, publishPrivateKey);
}

void KeyManager::PrivateKeys::save() {
  if (!sl) return;
  std::stringstream ss;
  concord::serialize::Serializable::serialize(ss, *this);
  sl->save(ss.str());
}

void KeyManager::PrivateKeys::load() {
  if (!sl) return;
  auto str = sl->load();
  std::stringstream ss;
  ss.write(str.c_str(), std::streamsize(str.size()));
  concord::serialize::Serializable::deserialize(ss, *this);
}

void KeyManager::FileSaver::save(const std::string& str) {
  std::ofstream myfile;
  if (!myfile.good()) return;
  myfile.open(fileName.c_str());
  myfile << str;
  myfile.close();
}

std::string KeyManager::FileSaver::load() {
  std::ifstream inFile;
  if (!inFile.good()) return "";
  inFile.open(fileName.c_str());
  std::stringstream strStream;
  strStream << inFile.rdbuf();
  inFile.close();
  return strStream.str();
}

}  // namespace bftEngine::impl