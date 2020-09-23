/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <folly/ScopeGuard.h>
#include <folly/ssl/OpenSSLCertUtils.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace fizz {

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P256>() {
  return {SignatureScheme::ecdsa_secp256r1_sha256};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P384>() {
  return {SignatureScheme::ecdsa_secp384r1_sha384};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P521>() {
  return {SignatureScheme::ecdsa_secp521r1_sha512};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::RSA>() {
  return {SignatureScheme::rsa_pss_sha256};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::ED25519>() {
  return {SignatureScheme::ed25519};
}
/*getSigSchemes defined by fzhang --start---*/
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::Dilithium2>() {
  return {SignatureScheme::dilithium2};
}
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P256_Dilithium2>() {
  return {SignatureScheme::p256_dilithium2};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::Dilithium3>() {
  return {SignatureScheme::dilithium3};
}
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P256_Dilithium3>() {
  return {SignatureScheme::p256_dilithium3};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::Dilithium4>() {
  return {SignatureScheme::dilithium4};
}
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P384_Dilithium4>() {
  return {SignatureScheme::p384_dilithium4};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::Mulan>() {
  return {SignatureScheme::mulan};
}
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P256_Mulan>() {
  return {SignatureScheme::p256_mulan};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::Aigis>() {
  return {SignatureScheme::aigis};
}
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P256_Aigis>() {
  return {SignatureScheme::p256_aigis};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::Falcon512>() {
  return {SignatureScheme::falcon512};
}
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P256_Falcon512>() {
  return {SignatureScheme::p256_falcon512};
}

template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::Falcon1024>() {
  return {SignatureScheme::falcon1024};
}
template <>
inline std::vector<SignatureScheme> CertUtils::getSigSchemes<KeyType::P521_Falcon1024>() {
  return {SignatureScheme::p521_falcon1024};
}
/*getSigSchemes defined by fzhang --end---*/

template <KeyType T>
SelfCertImpl<T>::SelfCertImpl(std::vector<folly::ssl::X509UniquePtr> certs)
    : certs_(std::move(certs)) {}

template <KeyType T>
SelfCertImpl<T>::SelfCertImpl(
    folly::ssl::EvpPkeyUniquePtr pkey,
    std::vector<folly::ssl::X509UniquePtr> certs,
    const std::vector<std::shared_ptr<fizz::CertificateCompressor>>&
        compressors) {
  if (certs.size() == 0) {
    throw std::runtime_error("Must supply at least 1 cert");
  }
  if (X509_check_private_key(certs[0].get(), pkey.get()) != 1) {
    throw std::runtime_error("Cert does not match private key");
  }
  // TODO: more strict validation of chaining requirements.
  signature_.setKey(std::move(pkey));
  certs_ = std::move(certs);
  for (const auto& compressor : compressors) {
    compressedCerts_[compressor->getAlgorithm()] =
        compressor->compress(getCertMessage());
  }
}

template <KeyType T>
std::string SelfCertImpl<T>::getIdentity() const {
  return folly::ssl::OpenSSLCertUtils::getCommonName(*certs_.front())
      .value_or("");
}

template <KeyType T>
std::vector<std::string> SelfCertImpl<T>::getAltIdentities() const {
  return folly::ssl::OpenSSLCertUtils::getSubjectAltNames(*certs_.front());
}

template <KeyType T>
CertificateMsg SelfCertImpl<T>::getCertMessage(
    Buf certificateRequestContext) const {
  return CertUtils::getCertMessage(
      certs_, std::move(certificateRequestContext));
}

template <KeyType T>
CompressedCertificate SelfCertImpl<T>::getCompressedCert(
    CertificateCompressionAlgorithm algo) const {
  return CertUtils::cloneCompressedCert(compressedCerts_.at(algo));
}

template <KeyType T>
std::vector<SignatureScheme> SelfCertImpl<T>::getSigSchemes() const {
  return CertUtils::getSigSchemes<T>();
}

template <>
inline Buf SelfCertImpl<KeyType::P256>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ecdsa_secp256r1_sha256:
      return signature_.sign<SignatureScheme::ecdsa_secp256r1_sha256>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::P384>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ecdsa_secp384r1_sha384:
      return signature_.sign<SignatureScheme::ecdsa_secp384r1_sha384>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::P521>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ecdsa_secp521r1_sha512:
      return signature_.sign<SignatureScheme::ecdsa_secp521r1_sha512>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::ED25519>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ed25519:
      return signature_.sign<SignatureScheme::ed25519>(signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::RSA>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::rsa_pss_sha256:
      return signature_.sign<SignatureScheme::rsa_pss_sha256>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

/*sign defined by fzhang ---start--- */
template <>
inline Buf SelfCertImpl<KeyType::Dilithium2>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::dilithium2:
      return signature_.sign<SignatureScheme::dilithium2>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline Buf SelfCertImpl<KeyType::P256_Dilithium2>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_dilithium2:
      return signature_.sign<SignatureScheme::p256_dilithium2>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::Dilithium3>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::dilithium3:
      return signature_.sign<SignatureScheme::dilithium3>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline Buf SelfCertImpl<KeyType::P256_Dilithium3>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_dilithium3:
      return signature_.sign<SignatureScheme::p256_dilithium3>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::Dilithium4>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::dilithium4:
      return signature_.sign<SignatureScheme::dilithium4>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline Buf SelfCertImpl<KeyType::P384_Dilithium4>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p384_dilithium4:
      return signature_.sign<SignatureScheme::p384_dilithium4>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::Mulan>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::mulan:
      return signature_.sign<SignatureScheme::mulan>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline Buf SelfCertImpl<KeyType::P256_Mulan>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_mulan:
      return signature_.sign<SignatureScheme::p256_mulan>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::Aigis>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::aigis:
      return signature_.sign<SignatureScheme::aigis>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline Buf SelfCertImpl<KeyType::P256_Aigis>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_aigis:
      return signature_.sign<SignatureScheme::p256_aigis>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::Falcon512>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::falcon512:
      return signature_.sign<SignatureScheme::falcon512>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline Buf SelfCertImpl<KeyType::P256_Falcon512>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_falcon512:
      return signature_.sign<SignatureScheme::p256_falcon512>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline Buf SelfCertImpl<KeyType::Falcon1024>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::falcon1024:
      return signature_.sign<SignatureScheme::falcon1024>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline Buf SelfCertImpl<KeyType::P521_Falcon1024>::sign(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p521_falcon1024:
      return signature_.sign<SignatureScheme::p521_falcon1024>(
          signData->coalesce());
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
/*sign defined by fzhang ---end--- */


template <KeyType T>
PeerCertImpl<T>::PeerCertImpl(folly::ssl::X509UniquePtr cert) {
  folly::ssl::EvpPkeyUniquePtr key(X509_get_pubkey(cert.get()));
  if (!key) {
    throw std::runtime_error("could not get key from cert");
  }
  signature_.setKey(std::move(key));
  cert_ = std::move(cert);
}

template <KeyType T>
std::string PeerCertImpl<T>::getIdentity() const {
  return folly::ssl::OpenSSLCertUtils::getCommonName(*cert_).value_or("");
}

template <>
inline void PeerCertImpl<KeyType::P256>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ecdsa_secp256r1_sha256:
      return signature_.verify<SignatureScheme::ecdsa_secp256r1_sha256>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::P384>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ecdsa_secp384r1_sha384:
      return signature_.verify<SignatureScheme::ecdsa_secp384r1_sha384>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::P521>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ecdsa_secp521r1_sha512:
      return signature_.verify<SignatureScheme::ecdsa_secp521r1_sha512>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::ED25519>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::ed25519:
      return signature_.verify<SignatureScheme::ed25519>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::RSA>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::rsa_pss_sha256:
      return signature_.verify<SignatureScheme::rsa_pss_sha256>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

/*verify defined by fzhang ---start--- */
template <>
inline void PeerCertImpl<KeyType::Dilithium2>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::dilithium2:
      return signature_.verify<SignatureScheme::dilithium2>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline void PeerCertImpl<KeyType::P256_Dilithium2>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_dilithium2:
      return signature_.verify<SignatureScheme::p256_dilithium2>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::Dilithium3>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::dilithium3:
      return signature_.verify<SignatureScheme::dilithium3>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline void PeerCertImpl<KeyType::P256_Dilithium3>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_dilithium3:
      return signature_.verify<SignatureScheme::p256_dilithium3>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::Dilithium4>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::dilithium4:
      return signature_.verify<SignatureScheme::dilithium4>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline void PeerCertImpl<KeyType::P384_Dilithium4>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p384_dilithium4:
      return signature_.verify<SignatureScheme::p384_dilithium4>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::Mulan>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::mulan:
      return signature_.verify<SignatureScheme::mulan>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline void PeerCertImpl<KeyType::P256_Mulan>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_mulan:
      return signature_.verify<SignatureScheme::p256_mulan>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::Aigis>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::aigis:
      return signature_.verify<SignatureScheme::aigis>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline void PeerCertImpl<KeyType::P256_Aigis>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_aigis:
      return signature_.verify<SignatureScheme::p256_aigis>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::Falcon512>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::falcon512:
      return signature_.verify<SignatureScheme::falcon512>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline void PeerCertImpl<KeyType::P256_Falcon512>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p256_falcon512:
      return signature_.verify<SignatureScheme::p256_falcon512>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}

template <>
inline void PeerCertImpl<KeyType::Falcon1024>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::falcon1024:
      return signature_.verify<SignatureScheme::falcon1024>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
template <>
inline void PeerCertImpl<KeyType::P521_Falcon1024>::verify(
    SignatureScheme scheme,
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned,
    folly::ByteRange signature) const {
  auto signData = CertUtils::prepareSignData(context, toBeSigned);
  switch (scheme) {
    case SignatureScheme::p521_falcon1024:
      return signature_.verify<SignatureScheme::p521_falcon1024>(
          signData->coalesce(), signature);
    default:
      throw std::runtime_error("Unsupported signature scheme");
  }
}
/*verify defined by fzhang ---end--- */

template <KeyType T>
folly::ssl::X509UniquePtr PeerCertImpl<T>::getX509() const {
  X509_up_ref(cert_.get());
  return folly::ssl::X509UniquePtr(cert_.get());
}

template <KeyType T>
folly::ssl::X509UniquePtr SelfCertImpl<T>::getX509() const {
  X509_up_ref(certs_.front().get());
  return folly::ssl::X509UniquePtr(certs_.front().get());
}
} // namespace fizz
