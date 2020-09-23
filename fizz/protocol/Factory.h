/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/RandomGenerator.h>
#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/AESGCM256.h>
#include <fizz/crypto/aead/AESOCB128.h>
#include <fizz/crypto/aead/ChaCha20Poly1305.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/crypto/exchange/ECCurveKeyExchange.h>
#include <fizz/crypto/exchange/KeyExchange.h>
#include <fizz/crypto/exchange/X25519.h>
#include <fizz/crypto/exchange/AKCNKeyExchange.h> //fzhang
#include <fizz/crypto/exchange/OQSKeyExchange.h> //fzhang
#include <fizz/crypto/exchange/HybridKeyExchange.h> //fzhang
#include <fizz/protocol/Certificate.h>
#include <fizz/protocol/HandshakeContext.h>
#include <fizz/protocol/KeyScheduler.h>
#include <fizz/record/EncryptedRecordLayer.h>
#include <fizz/record/PlaintextRecordLayer.h>
#include <fizz/record/Types.h>

namespace fizz {

/**
 * This class instantiates various objects to facilitate testing.
 */
class Factory {
 public:
  virtual ~Factory() = default;

  virtual std::unique_ptr<PlaintextReadRecordLayer>
  makePlaintextReadRecordLayer() const {
    return std::make_unique<PlaintextReadRecordLayer>();
  }

  virtual std::unique_ptr<PlaintextWriteRecordLayer>
  makePlaintextWriteRecordLayer() const {
    return std::make_unique<PlaintextWriteRecordLayer>();
  }

  virtual std::unique_ptr<EncryptedReadRecordLayer>
  makeEncryptedReadRecordLayer(EncryptionLevel encryptionLevel) const {
    return std::make_unique<EncryptedReadRecordLayer>(encryptionLevel);
  }

  virtual std::unique_ptr<EncryptedWriteRecordLayer>
  makeEncryptedWriteRecordLayer(EncryptionLevel encryptionLevel) const {
    return std::make_unique<EncryptedWriteRecordLayer>(encryptionLevel);
  }

  virtual std::unique_ptr<KeyScheduler> makeKeyScheduler(
      CipherSuite cipher) const {
    auto keyDer = makeKeyDeriver(cipher);
    return std::make_unique<KeyScheduler>(std::move(keyDer));
  }

  virtual std::unique_ptr<KeyDerivation> makeKeyDeriver(
      CipherSuite cipher) const = 0;

  virtual std::unique_ptr<HandshakeContext> makeHandshakeContext(
      CipherSuite cipher) const = 0;

  virtual std::unique_ptr<KeyExchange> makeKeyExchange(NamedGroup group) const {
    switch (group) {
      case NamedGroup::secp256r1:
        return std::make_unique<OpenSSLECKeyExchange<P256>>();
      case NamedGroup::secp384r1:
        return std::make_unique<OpenSSLECKeyExchange<P384>>();
      case NamedGroup::secp521r1:
        return std::make_unique<OpenSSLECKeyExchange<P521>>();
      case NamedGroup::x25519:
        return std::make_unique<X25519KeyExchange>();
      /******************************fzhang start******************************/
      case NamedGroup::kyber512: 
        return std::make_unique<OQSKeyExchange<Kyber512>>();
      case NamedGroup::kyber768: 
        return std::make_unique<OQSKeyExchange<Kyber768>>();
      case NamedGroup::kyber1024:
        return std::make_unique<OQSKeyExchange<Kyber1024>>();
      case NamedGroup::lightsaber: 
        return std::make_unique<OQSKeyExchange<LightSaber>>();
      case NamedGroup::saber: 
        return std::make_unique<OQSKeyExchange<Saber>>();
      case NamedGroup::firesaber: 
        return std::make_unique<OQSKeyExchange<FireSaber>>();
      case NamedGroup::ntru509:
        return std::make_unique<OQSKeyExchange<NTRU509>>();
      case NamedGroup::ntru677: 
        return std::make_unique<OQSKeyExchange<NTRU677>>();
      case NamedGroup::ntru821:
        return std::make_unique<OQSKeyExchange<NTRU821>>();
      case NamedGroup::akcn:
        return std::make_unique<AKCNKeyExchange>();
      case NamedGroup::p256_kyber512: 
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P256>,OQSKeyExchange<Kyber512>>>(65u);
      case NamedGroup::p384_kyber768: 
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P384>,OQSKeyExchange<Kyber768>>>(97u); 
      case NamedGroup::p521_kyber1024:
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P521>,OQSKeyExchange<Kyber1024>>>(133u);
      case NamedGroup::p256_lightsaber: 
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P256>,OQSKeyExchange<LightSaber>>>(65u);
      case NamedGroup::p384_saber: 
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P384>,OQSKeyExchange<Saber>>>(97u); 
      case NamedGroup::p521_firesaber: 
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P521>,OQSKeyExchange<FireSaber>>>(133u);
      case NamedGroup::p256_ntru509: 
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P256>,OQSKeyExchange<NTRU509>>>(65u);
      case NamedGroup::p384_ntru677:
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P384>,OQSKeyExchange<NTRU677>>>(97u); 
      case NamedGroup::p521_ntru821:
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P521>,OQSKeyExchange<NTRU821>>>(133u);
      
      case NamedGroup::akcn_hybrid: //fzhang+akcn
        return std::make_unique<HybridKeyExchange<OpenSSLECKeyExchange<P384>,AKCNKeyExchange>>(97u); 
      /******************************fzhang start******************************/
      default:
        throw std::runtime_error("ke: not implemented");
    }
  }

  virtual std::unique_ptr<Aead> makeAead(CipherSuite cipher) const {
    switch (cipher) {
      case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        return OpenSSLEVPCipher::makeCipher<ChaCha20Poly1305>();
      case CipherSuite::TLS_AES_128_GCM_SHA256:
        return OpenSSLEVPCipher::makeCipher<AESGCM128>();
      case CipherSuite::TLS_AES_256_GCM_SHA384:
        return OpenSSLEVPCipher::makeCipher<AESGCM256>();
      case CipherSuite::TLS_AES_128_OCB_SHA256_EXPERIMENTAL:
        return OpenSSLEVPCipher::makeCipher<AESOCB128>();
      default:
        throw std::runtime_error("aead: not implemented");
    }
  }

  virtual Random makeRandom() const {
    return RandomGenerator<Random().size()>().generateRandom();
  }

  virtual uint32_t makeTicketAgeAdd() const {
    return RandomNumGenerator<uint32_t>().generateRandom();
  }

  virtual std::shared_ptr<PeerCert> makePeerCert(
      CertificateEntry certEntry,
      bool /*leaf*/) const {
    return CertUtils::makePeerCert(std::move(certEntry.cert_data));
  }

  virtual std::string getHkdfPrefix() const {
    return kHkdfLabelPrefix.str();
  }
};
} // namespace fizz
