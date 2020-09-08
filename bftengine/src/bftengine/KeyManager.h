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

#pragma once

#include "InternalBFTClient.h"
#include "KeyStore.h"
#include "ReplicaImp.hpp"
#include "CryptoManager.hpp"
#include "bftengine/MultiSignatureInterfaces.hpp"
#include "Timers.hpp"
#include "Metrics.hpp"

namespace bftEngine::impl {

class KeyManager {
 public:
  void sendKeyExchange();
  void sendInitialKey();
  std::string onKeyExchange(KeyExchangeMsg& kemsg, const uint64_t& sn);
  void onCheckpoint(const int& num);
  void registerForNotification(IKeyExchanger* ke);
  KeyExchangeMsg getReplicaKey(const uint16_t& repID) const;
  std::string getPrivateKey() { return prvKeys_.privateKey; }
  void loadKeysFromReservedPages();

  std::atomic_bool keysExchanged{false};

  // A private key has three states
  // 1 - published to consensus.
  // 2 - after consesnsus i.e. oustanding
  // 3 - after desired check point i.e. the private key of the replica
  // all three fields may be populated simulatanously

  struct FileSaver : public ISaverLoader {
    std::string fileName{"./tmp_store"};
    void save(const std::string& str);
    std::string load();
  };
  struct PrivateKeys : public concord::serialize::SerializableFactory<PrivateKeys> {
    std::string publishPrivateKey;
    std::string outstandingPrivateKey;
    std::string privateKey;
    static void rotate(std::string& dst, std::string& src);
    std::shared_ptr<ISaverLoader> sl{nullptr};

    void save();
    void load();

   protected:
    const std::string getVersion() const;
    void serializeDataMembers(std::ostream& outStream) const;
    void deserializeDataMembers(std::istream& inStream);
  };

  static KeyManager& get(IinternalBFTClient* cl = nullptr,
                         const int id = 0,
                         const uint32_t clusterSize = 0,
                         IReservedPages* reservedPages = nullptr,
                         const uint32_t sizeOfReservedPage = 0,
                         IPathDetector* pathDetect = nullptr,
                         IKeyGenerator* kg = nullptr,
                         std::shared_ptr<ISaverLoader>* sl = nullptr,
                         concordUtil::Timers* timers = nullptr) {
    static KeyManager km{cl, id, clusterSize, reservedPages, sizeOfReservedPage, pathDetect, kg, sl, *timers};
    return km;
  }

  static void start(InternalBFTClient* cl,
                    const int id,
                    const uint32_t clusterSize,
                    IReservedPages* reservedPages,
                    const uint32_t sizeOfReservedPage,
                    IPathDetector* pathDetect,
                    IKeyGenerator* kg,
                    std::shared_ptr<ISaverLoader>* sl,
                    concordUtil::Timers* timers,
                    std::shared_ptr<concordMetrics::Aggregator> a,
                    std::chrono::seconds interval) {
    get(cl, id, clusterSize, reservedPages, sizeOfReservedPage, pathDetect, kg, sl, timers);
    get().initMetrics(a, interval);
  }

 private:
  KeyManager(IinternalBFTClient* cl,
             const int& id,
             const uint32_t& clusterSize,
             IReservedPages* reservedPages,
             const uint32_t sizeOfReservedPage,
             IPathDetector* pathDetect,
             IKeyGenerator* kg,
             std::shared_ptr<ISaverLoader>* sl,
             concordUtil::Timers& timers);

  uint16_t repID_{};
  uint32_t clusterSize_{};
  std::string generateCid();
  // Raw pointer is ok, since this class does not manage this resource.
  IinternalBFTClient* client_{nullptr};

  std::vector<IKeyExchanger*> registryToExchange_;
  ClusterKeyStore keyStore_;

  PrivateKeys prvKeys_;
  IPathDetector* pathDetector_{nullptr};
  IKeyGenerator* keygen_{nullptr};
  void onInitialKeyExchange(KeyExchangeMsg& kemsg, const uint64_t& sn);

  //////////////////////////////////////////////////
  // METRICS
  struct Metrics {
    std::chrono::seconds lastMetricsDumpTime;
    std::chrono::seconds metricsDumpIntervalInSec;
    std::shared_ptr<concordMetrics::Aggregator> aggregator;
    concordMetrics::Component component;
    concordMetrics::CounterHandle keyExchangedCounter;
    concordMetrics::CounterHandle keyExchangedOnStartCounter;
    concordMetrics::CounterHandle publicKeyRotated;
    void setAggregator(std::shared_ptr<concordMetrics::Aggregator> a) {
      aggregator = a;
      component.SetAggregator(aggregator);
    }
    Metrics(std::shared_ptr<concordMetrics::Aggregator> a, std::chrono::seconds interval)
        : lastMetricsDumpTime{0},
          metricsDumpIntervalInSec{interval},
          aggregator(a),
          component{"KeyManager", aggregator},
          keyExchangedCounter{component.RegisterCounter("KeyExchangedCounter")},
          keyExchangedOnStartCounter{component.RegisterCounter("KeyExchangedOnStartCounter")},
          publicKeyRotated{component.RegisterCounter("publicKeyRotated")} {}
  };

  std::unique_ptr<Metrics> metrics_;
  void initMetrics(std::shared_ptr<concordMetrics::Aggregator> a, std::chrono::seconds interval);
  ///////////////////////////////////////////////////
  // Timers
  concordUtil::Timers::Handle metricsTimer_;
  concordUtil::Timers& timers_;

  // deleted
  KeyManager(const KeyManager&) = delete;
  KeyManager(const KeyManager&&) = delete;
  KeyManager& operator=(const KeyManager&) = delete;
  KeyManager& operator=(const KeyManager&&) = delete;

  friend class TestKeyManager;
};

class LogPathDetector : public IPathDetector {
  SequenceWithActiveWindow<kWorkWindowSize, 1, SeqNum, SeqNumInfo, SeqNumInfo>& mainLog_;

 public:
  LogPathDetector(SequenceWithActiveWindow<kWorkWindowSize, 1, SeqNum, SeqNumInfo, SeqNumInfo>* mainLog)
      : mainLog_(*mainLog) {}
  virtual bool isSlowPath(const uint64_t& sn) { return mainLog_.get(sn).slowPathStarted(); }
};

class TestKeyManager {
 public:
  TestKeyManager(IinternalBFTClient* cl,
                 const int& id,
                 const uint32_t& clusterSize,
                 IReservedPages* reservedPages,
                 const uint32_t sizeOfReservedPage,
                 IPathDetector* pathDetect,
                 IKeyGenerator* kg,
                 std::shared_ptr<ISaverLoader>* sl,
                 concordUtil::Timers& timers)
      : km_(cl, id, clusterSize, reservedPages, sizeOfReservedPage, pathDetect, kg, sl, timers),
        a(new concordMetrics::Aggregator()) {
    km_.initMetrics(a, std::chrono::seconds(600));
  }
  KeyManager km_;
  std::shared_ptr<concordMetrics::Aggregator> a;
  uint64_t getKeyExchangedCounter() { return km_.metrics_->keyExchangedCounter.Get().Get(); }
  uint64_t getKeyExchangedOnStartCounter() { return km_.metrics_->keyExchangedOnStartCounter.Get().Get(); }
  uint64_t getPublicKeyRotated() { return km_.metrics_->publicKeyRotated.Get().Get(); }
};

}  // namespace bftEngine::impl