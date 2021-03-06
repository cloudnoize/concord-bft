// Concord
//
// Copyright (c) 2018-2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0
// License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.
// This module creates an instance of ClientImp class using input
// parameters and launches a bunch of tests created by TestsBuilder towards
// concord::consensus::ReplicaImp objects.

#include <getopt.h>

#include "communication/CommFactory.hpp"
#include "bftclient/config.h"
#include "bftclient/bft_client.h"
#include "config/test_comm_config.hpp"
#include "config.hpp"
#include "poll_based_state_client.hpp"
#include "client_reconfiguration_engine.hpp"
#include <variant>

using namespace bftEngine;
using namespace bft::communication;

using std::string;
using bft::client::ClientConfig;
using bft::client::ClientId;
using bft::client::Client;
struct creParams {
  string commConfigFile;
  string certFolder;
  ClientConfig bftConfig;
  cre::Config CreConfig;
};
creParams setupCreParams(int argc, char** argv) {
  // We assume that cre bft client is the highest external client id in the system
  static struct option longOptions[] = {{"id", required_argument, 0, 'i'},
                                        {"fval", required_argument, 0, 'f'},
                                        {"cval", required_argument, 0, 'c'},
                                        {"replicas", required_argument, 0, 'r'},
                                        {"network-configuration-file", optional_argument, 0, 'n'},
                                        {"cert-folder", optional_argument, 0, 'k'},
                                        {"txn-signing-key-path", optional_argument, 0, 't'},
                                        {"interval-timeout", optional_argument, 0, 'o'},
                                        {0, 0, 0, 0}};
  creParams cre_param;
  ClientConfig& client_config = cre_param.bftConfig;
  int o = 0;
  int optionIndex = 0;
  LOG_INFO(GL, "Command line options:");
  while ((o = getopt_long(argc, argv, "i:f:c:r:n:k:t:o:", longOptions, &optionIndex)) != -1) {
    switch (o) {
      case 'i': {
        client_config.id = ClientId{concord::util::to<uint16_t>(optarg)};
        cre_param.CreConfig.id_ = concord::util::to<uint16_t>(optarg);
      } break;

      case 'f': {
        client_config.f_val = concord::util::to<uint16_t>(optarg);
      } break;

      case 'c': {
        client_config.c_val = concord::util::to<uint16_t>(optarg);
      } break;

      case 'r': {
        int tempnVal = concord::util::to<uint32_t>(optarg);
        for (int i = 0; i < tempnVal; i++) {
          client_config.all_replicas.emplace(bft::client::ReplicaId{static_cast<uint16_t>(i)});
        }
      } break;

      case 'n': {
        cre_param.commConfigFile = optarg;
      } break;

      case 't': {
        client_config.transaction_signing_private_key_file_path = optarg;
      } break;

      case 'o': {
        cre_param.CreConfig.interval_timeout_ms_ = concord::util::to<uint64_t>(optarg);
      } break;

      case 'k': {
        cre_param.certFolder = optarg;
      } break;

      case '?': {
        throw std::runtime_error("invalid arguments");
      } break;

      default:
        break;
    }
  }
  return cre_param;
}

auto logger = logging::getLogger("skvbtest.cre");

ICommunication* createCommunication(const ClientConfig& cc,
                                    const std::string& commFileName,
                                    const std::string& certFolder) {
  TestCommConfig testCommConfig(logger);
  uint16_t numOfReplicas = cc.all_replicas.size();
  uint16_t clients = cc.id.val;
#ifdef USE_COMM_PLAIN_TCP
  PlainTcpConfig conf = testCommConfig.GetTCPConfig(false, cc.id.val, clients, numOfReplicas, commFileName);
#elif USE_COMM_TLS_TCP
  TlsTcpConfig conf =
      testCommConfig.GetTlsTCPConfig(false, cc.id.val, clients, numOfReplicas, commFileName, certFolder);
#else
  PlainUdpConfig conf = testCommConfig.GetUDPConfig(false, cc.id.val, clients, numOfReplicas, commFileName);
#endif

  return CommFactory::create(conf);
}

class KeyExchangeCommandHandler : public cre::IStateHandler {
 public:
  KeyExchangeCommandHandler(uint16_t clientId) : clientId_{clientId} {}
  bool validate(const cre::State& state) const {
    concord::messages::ClientReconfigurationStateReply crep;
    concord::messages::deserialize(state.data, crep);
    return std::holds_alternative<concord::messages::ClientKeyExchangeCommand>(crep.response);
  };
  bool execute(const cre::State& state, cre::WriteState& out) {
    LOG_INFO(getLogger(), "execute key exchange request");
    concord::messages::ClientReconfigurationStateReply crep;
    concord::messages::deserialize(state.data, crep);
    concord::messages::ClientKeyExchangeCommand command =
        std::get<concord::messages::ClientKeyExchangeCommand>(crep.response);

    concord::messages::ReconfigurationRequest rreq;
    concord::messages::ClientExchangePublicKey creq;
    std::string new_pub_key = "test_pub_key";
    creq.sender_id = clientId_;
    creq.pub_key = new_pub_key;
    rreq.command = creq;
    std::vector<uint8_t> req_buf;
    concord::messages::serialize(req_buf, rreq);
    out = {req_buf, [this, new_pub_key]() {
             LOG_INFO(this->getLogger(), "writing new public key success, public key is: " << new_pub_key);
           }};
    return true;
  }

 private:
  logging::Logger getLogger() {
    static logging::Logger logger_(logging::getLogger("cre.stateHandler.KeyExchangeHandler"));
    return logger_;
  }
  uint16_t clientId_;
};

class PublicKeyExchangeHandler : public cre::IStateHandler {
 public:
  bool validate(const cre::State& state) const override {
    concord::messages::ClientReconfigurationStateReply crep;
    concord::messages::deserialize(state.data, crep);
    return std::holds_alternative<concord::messages::ClientExchangePublicKey>(crep.response);
  }
  bool execute(const cre::State&, cre::WriteState&) override {
    LOG_INFO(getLogger(), "restart client components");
    return true;
  }
  logging::Logger getLogger() {
    static logging::Logger logger_(logging::getLogger("cre.stateHandler.PublicKeyExchange"));
    return logger_;
  }
};

int main(int argc, char** argv) {
  auto creParams = setupCreParams(argc, argv);
  std::unique_ptr<ICommunication> comm_ptr(
      createCommunication(creParams.bftConfig, creParams.commConfigFile, creParams.certFolder));
  Client* bft_client = new Client(std::move(comm_ptr), creParams.bftConfig);
  cre::IStateClient* pollBasedClient =
      new cre::PollBasedStateClient(bft_client, creParams.CreConfig.interval_timeout_ms_, 0, creParams.CreConfig.id_);
  cre::ClientReconfigurationEngine cre(
      creParams.CreConfig, pollBasedClient, std::make_shared<concordMetrics::Aggregator>());
  cre.registerHandler(std::make_shared<KeyExchangeCommandHandler>(creParams.CreConfig.id_));
  cre.registerHandler(std::make_shared<PublicKeyExchangeHandler>());
  cre.start();
  while (true) std::this_thread::sleep_for(1s);
}
