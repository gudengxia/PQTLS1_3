/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/record/Types.h>
#include <map>

namespace fizz {
template <>
inline CipherSuite parse(folly::StringPiece s) {
  static const std::map<folly::StringPiece, CipherSuite> stringToCiphers = {
      {"TLS_AES_128_GCM_SHA256", CipherSuite::TLS_AES_128_GCM_SHA256},
      {"TLS_AES_256_GCM_SHA384", CipherSuite::TLS_AES_256_GCM_SHA384},
      {"TLS_CHACHA20_POLY1305_SHA256",
       CipherSuite::TLS_CHACHA20_POLY1305_SHA256},
      {"TLS_AES_128_OCB_SHA256_EXPERIMENTAL",
       CipherSuite::TLS_AES_128_OCB_SHA256_EXPERIMENTAL}};

  auto location = stringToCiphers.find(s);
  if (location != stringToCiphers.end()) {
    return location->second;
  }

  throw std::runtime_error(folly::to<std::string>("Unknown cipher suite: ", s));
}

template <>
inline SignatureScheme parse(folly::StringPiece s) {
  static const std::map<folly::StringPiece, SignatureScheme> stringToSchemes = {
      {"ecdsa_secp256r1_sha256", SignatureScheme::ecdsa_secp256r1_sha256}, {"ecdsa_secp384r1_sha384", SignatureScheme::ecdsa_secp384r1_sha384},
      {"ecdsa_secp521r1_sha512", SignatureScheme::ecdsa_secp521r1_sha512}, {"rsa_pss_sha256", SignatureScheme::rsa_pss_sha256},
      {"rsa_pss_sha384", SignatureScheme::rsa_pss_sha384}, {"rsa_pss_sha512", SignatureScheme::rsa_pss_sha512},
      {"ed25519", SignatureScheme::ed25519}, {"ed448", SignatureScheme::ed448},
      {"dilithium2", SignatureScheme::dilithium2}, {"p256_dilithium2", SignatureScheme::p256_dilithium2},
      {"dilithium3", SignatureScheme::dilithium3}, {"p256_dilithium3", SignatureScheme::p256_dilithium3},
      {"dilithium4", SignatureScheme::dilithium4}, {"p384_dilithium4", SignatureScheme::p384_dilithium4},
      {"falcon512", SignatureScheme::falcon512}, {"p256_falcon512", SignatureScheme::falcon512},
      {"falcon1024",SignatureScheme::falcon1024}, {"p521_falcon1024", SignatureScheme::p521_falcon1024},
      {"mulan", SignatureScheme::mulan}, {"p256_mulan", SignatureScheme::p256_mulan},
      {"aigis", SignatureScheme::aigis}, {"p256_aigis", SignatureScheme::p256_aigis}}; //fzhang

  auto location = stringToSchemes.find(s);
  if (location != stringToSchemes.end()) {
    return location->second;
  }

  throw std::runtime_error(
      folly::to<std::string>("Unknown signature scheme: ", s));
}

template <>
inline NamedGroup parse(folly::StringPiece s) {
  static const std::map<folly::StringPiece, NamedGroup> stringToGroups = {
      {"secp256r1", NamedGroup::secp256r1},{"secp384r1", NamedGroup::secp384r1}, 
      {"x25519", NamedGroup::x25519}, {"secp521r1", NamedGroup::secp521r1}, 
      {"kyber512", NamedGroup::kyber512}, {"kyber768", NamedGroup::kyber768}, {"kyber1024", NamedGroup::kyber1024}, 
      {"lightsaber", NamedGroup::lightsaber}, {"saber", NamedGroup::saber}, {"firesaber", NamedGroup::firesaber}, 
      {"ntru509", NamedGroup::ntru509}, {"ntru677", NamedGroup::ntru677}, {"ntru821", NamedGroup::ntru821},
      {"p256_kyber512", NamedGroup::p256_kyber512}, {"p384_kyber768", NamedGroup::p384_kyber768}, {"p521_kyber1024", NamedGroup::p521_kyber1024}, 
      {"p256_lightsaber", NamedGroup::p256_lightsaber}, {"p384_saber", NamedGroup::p384_saber}, {"p521_firesaber", NamedGroup::p521_firesaber},
      {"p256_ntru509", NamedGroup::p256_ntru509}, {"p384_ntru677", NamedGroup::p384_ntru677}, {"p521_ntru821", NamedGroup::p521_ntru821},
      {"akcn", NamedGroup::akcn},  {"akcn_hybrid", NamedGroup::akcn_hybrid}}; //fzhang

  auto location = stringToGroups.find(s);
  if (location != stringToGroups.end()) {
    return location->second;
  }

  throw std::runtime_error(folly::to<std::string>("Unknown named group: ", s));
}

template <>
inline CertificateCompressionAlgorithm parse(folly::StringPiece s) {
  static const std::map<folly::StringPiece, CertificateCompressionAlgorithm>
      stringToAlgos = {{"zlib", CertificateCompressionAlgorithm::zlib},
                       {"brotli", CertificateCompressionAlgorithm::brotli},
                       {"zstd", CertificateCompressionAlgorithm::zstd}};

  auto location = stringToAlgos.find(s);
  if (location != stringToAlgos.end()) {
    return location->second;
  }

  throw std::runtime_error(
      folly::to<std::string>("Unknown compression algorithm: ", s));
}
} // namespace fizz
