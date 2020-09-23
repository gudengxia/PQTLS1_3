/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBuf.h>

#include <fizz/protocol/Events.h>

namespace fizz {

constexpr folly::StringPiece kHkdfLabelPrefix = "tls13 ";

using Buf = std::unique_ptr<folly::IOBuf>;

enum class ProtocolVersion : uint16_t {
  tls_1_0 = 0x0301,
  tls_1_1 = 0x0302,
  tls_1_2 = 0x0303,
  tls_1_3 = 0x0304,
  tls_1_3_23 = 0x7f17,
  tls_1_3_23_fb = 0xfb17,
  tls_1_3_26 = 0x7f1a,
  tls_1_3_26_fb = 0xfb1a,
  tls_1_3_28 = 0x7f1c,
};

ProtocolVersion getRealDraftVersion(ProtocolVersion);

std::string toString(ProtocolVersion);

enum class ContentType : uint8_t {
  alert = 21,
  handshake = 22,
  application_data = 23,

  change_cipher_spec = 20,
};

struct TLSMessage {
  ContentType type;
  Buf fragment;
};

constexpr folly::StringPiece FakeChangeCipherSpec{"\x14\x03\x03\x00\x01\x01",
                                                  6};

enum class HandshakeType : uint8_t {
  client_hello = 1,
  server_hello = 2,
  new_session_ticket = 4,
  end_of_early_data = 5,
  hello_retry_request = 6,
  encrypted_extensions = 8,
  certificate = 11,
  certificate_request = 13,
  certificate_verify = 15,
  finished = 20,
  key_update = 24,
  compressed_certificate = 25,
  message_hash = 254,
};

constexpr size_t kMaxHandshakeSize = 0x20000; // 128k

struct message_hash {
  static constexpr HandshakeType handshake_type = HandshakeType::message_hash;
  std::unique_ptr<folly::IOBuf> hash;
};

template <Event e, HandshakeType t>
struct HandshakeStruct : EventType<e> {
  static constexpr HandshakeType handshake_type = t;

  /*
   * Original encoding of the message, populated on received handshake messages.
   */
  folly::Optional<Buf> originalEncoding;
};

enum class ExtensionType : uint16_t {
  server_name = 0,
  supported_groups = 10,
  signature_algorithms = 13,
  application_layer_protocol_negotiation = 16,
  token_binding = 24,
  compress_certificate = 27,
  delegated_credential = 34,
  pre_shared_key = 41,
  early_data = 42,
  supported_versions = 43,
  cookie = 44,
  psk_key_exchange_modes = 45,
  certificate_authorities = 47,
  post_handshake_auth = 49,
  signature_algorithms_cert = 50,
  key_share = 51,
  quic_transport_parameters = 0xffa5,

  // alternate_server_name = 0xfb00,
  // draft_delegated_credential = 0xff02,
  test_extension = 0xff03,
  thrift_parameters = 0xff41,
};

std::string toString(ExtensionType);

enum class AlertDescription : uint8_t {
  close_notify = 0,
  end_of_early_data = 1,
  unexpected_message = 10,
  bad_record_mac = 20,
  record_overflow = 22,
  handshake_failure = 40,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  illegal_parameter = 47,
  unknown_ca = 48,
  access_denied = 49,
  decode_error = 50,
  decrypt_error = 51,
  protocol_version = 70,
  insufficient_security = 71,
  internal_error = 80,
  inappropriate_fallback = 86,
  user_canceled = 90,
  missing_extension = 109,
  unsupported_extension = 110,
  certificate_unobtainable = 111,
  unrecognized_name = 112,
  bad_certificate_status_response = 113,
  bad_certificate_hash_value = 114,
  unknown_psk_identity = 115,
  certificate_required = 116,
  no_application_protocol = 120
};

std::string toString(AlertDescription);

enum class CipherSuite : uint16_t {
  TLS_AES_128_GCM_SHA256 = 0x1301,
  TLS_AES_256_GCM_SHA384 = 0x1302,
  TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
  // experimental cipher suites
  TLS_AES_128_OCB_SHA256_EXPERIMENTAL = 0xFF01
};

std::string toString(CipherSuite);

enum class PskKeyExchangeMode : uint8_t { psk_ke = 0, psk_dhe_ke = 1 };

std::string toString(PskKeyExchangeMode);

enum class CertificateCompressionAlgorithm : uint16_t {
  zlib = 1,
  brotli = 2,
  zstd = 3,
};

std::string toString(CertificateCompressionAlgorithm);

struct Extension {
  ExtensionType extension_type;
  Buf extension_data; // Limited to 2^16-1 bytes.
};

struct HkdfLabel {
  uint16_t length;
  const std::string label;
  Buf hash_value;
};

using Random = std::array<uint8_t, 32>;

struct ClientHello
    : HandshakeStruct<Event::ClientHello, HandshakeType::client_hello> {
  ProtocolVersion legacy_version = ProtocolVersion::tls_1_2;
  Random random;
  Buf legacy_session_id;
  std::vector<CipherSuite> cipher_suites;
  std::vector<uint8_t> legacy_compression_methods;
  std::vector<Extension> extensions;
};

struct ServerHello
    : HandshakeStruct<Event::ServerHello, HandshakeType::server_hello> {
  ProtocolVersion legacy_version = ProtocolVersion::tls_1_2;
  Random random;
  // If legacy_session_id_echo is non-null the ServerHello will be encoded with
  // it and legacy_compression_method.
  Buf legacy_session_id_echo;
  CipherSuite cipher_suite;
  uint8_t legacy_compression_method{0};
  std::vector<Extension> extensions;
};

struct HelloRetryRequest
    : HandshakeStruct<Event::HelloRetryRequest, HandshakeType::server_hello> {
  ProtocolVersion legacy_version = ProtocolVersion::tls_1_2;
  static constexpr Random HrrRandom{
      {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
       0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
       0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}};
  Buf legacy_session_id_echo;
  CipherSuite cipher_suite;
  uint8_t legacy_compression_method{0};
  std::vector<Extension> extensions;
};

struct EndOfEarlyData
    : HandshakeStruct<Event::EndOfEarlyData, HandshakeType::end_of_early_data> {
};

struct EncryptedExtensions : HandshakeStruct<
                                 Event::EncryptedExtensions,
                                 HandshakeType::encrypted_extensions> {
  std::vector<Extension> extensions;
};

struct CertificateEntry {
  Buf cert_data;
  std::vector<Extension> extensions;
};

struct CertificateMsg
    : HandshakeStruct<Event::Certificate, HandshakeType::certificate> {
  Buf certificate_request_context;
  std::vector<CertificateEntry> certificate_list;
};

struct CompressedCertificate : HandshakeStruct<
                                   Event::CompressedCertificate,
                                   HandshakeType::compressed_certificate> {
  CertificateCompressionAlgorithm algorithm;
  uint32_t uncompressed_length;
  Buf compressed_certificate_message;
};

struct CertificateRequest : HandshakeStruct<
                                Event::CertificateRequest,
                                HandshakeType::certificate_request> {
  Buf certificate_request_context;
  std::vector<Extension> extensions;
};

enum class SignatureScheme : uint16_t {
  ecdsa_secp256r1_sha256 = 0x0403,
  ecdsa_secp384r1_sha384 = 0x0503,
  ecdsa_secp521r1_sha512 = 0x0603,
  rsa_pss_sha256 = 0x0804,
  rsa_pss_sha384 = 0x0805,
  rsa_pss_sha512 = 0x0806,
  ed25519 = 0x0807,
  ed448 = 0x0808,
  // all batch scheme type numbers are temporarially assigned
  ecdsa_secp256r1_sha256_batch = 0xFF00,
  ecdsa_secp384r1_sha384_batch = 0xFF01,
  ecdsa_secp521r1_sha512_batch = 0xFF02,
  ed25519_batch = 0xFF03,
  ed448_batch = 0xFF04,
  rsa_pss_sha256_batch = 0xFF05, 
  //fzhang: To avoid conflict to oqs_signaturescheme,the IDs of batch scheme 
  //are changed from 0xFE__ to 0xFF__

  /*keep line with opensll_oqs*/
  dilithium2 = 0xfe03, 
  p256_dilithium2 = 0xfe04, 
  rsa3072_dilithium2 = 0xfe05, 
  dilithium3 = 0xfe06, 
  dilithium4 = 0xfe07, 
  p384_dilithium4 = 0xfe08,
  falcon512 = 0xfe0b,
  p256_falcon512 = 0xfe0c,
  rsa3072_falcon512 = 0xfe0d,
  falcon1024 = 0xfe0e,
  p521_falcon1024 = 0xfe0f,
  /*keep line with opensll_oqs*/

  /*defined by fzhang*/
  mulan = 0xfef0,
  p256_mulan = 0xfef1,
  p256_dilithium3 = 0xfef2,
  aigis = 0xfef3,
  p256_aigis = 0xfff4
  /*defined by fzhang*/
};

// TODO: Extend the BatchSchemeInfo to be:
//       struct BatchSchemeInfo {
//         SignatureScheme baseScheme;
//         Hasher hasher;
//       };
struct BatchSchemeInfo {
  SignatureScheme baseScheme;
};

/**
 * Try to get information of a batch signature scheme.
 *
 * If @param supportedBaseSchemes is empty, the applicable base signature scheme
 * will be returned directly.
 *
 * @return folly::none if @param batchScheme is not a batch signature scheme or
 *         the base signature scheme is not in @param supportedBaseSchemes.
 */
folly::Optional<BatchSchemeInfo> getBatchSchemeInfo(
    SignatureScheme batchScheme,
    const std::vector<SignatureScheme>& supportedBaseSchemes = {});

std::string toString(SignatureScheme);

struct CertificateVerify : HandshakeStruct<
                               Event::CertificateVerify,
                               HandshakeType::certificate_verify> {
  SignatureScheme algorithm;
  Buf signature;
};

struct Finished : HandshakeStruct<Event::Finished, HandshakeType::finished> {
  Buf verify_data;
};

struct NewSessionTicket : HandshakeStruct<
                              Event::NewSessionTicket,
                              HandshakeType::new_session_ticket> {
  uint32_t ticket_lifetime;
  uint32_t ticket_age_add;
  // Ticket nonce is set to null iff pre-draft 21.
  Buf ticket_nonce;
  Buf ticket;
  std::vector<Extension> extensions;
};

enum class KeyUpdateRequest : uint8_t {
  update_not_requested = 0,
  update_requested = 1
};

struct KeyUpdate
    : HandshakeStruct<Event::KeyUpdate, HandshakeType::key_update> {
  KeyUpdateRequest request_update;
};

enum class NamedGroup : uint16_t {
  secp256r1 = 23,
  secp384r1 = 24,
  secp521r1 = 25,
  x25519 = 29,
  /*fzhang:keep line with openssl_oqs*/
  frodo640 = 0x0200, 
  frodo976 = 0x0202,
  frodo1344 = 0x0204,
  kyber512 = 0x020F, 
  kyber768 = 0x0210, 
  kyber1024 = 0x0211, 
  newhope512 = 0x0212, 
  newhope1024 = 0x0213,
  ntru509 = 0x0214,
  ntru677 = 0x0215,
  ntru821 = 0x0216,
  lightsaber = 0x0217,
  saber = 0x0218,
  firesaber = 0x0219,
  sike503 = 0x0220, 
  sike751 = 0x0222, 
  p256_ntru509 = 0x2F14,
  p384_ntru677 = 0x2F15,
  p521_ntru821 = 0x2F16,
  p256_lightsaber = 0x2F18,
  p384_saber = 0x2F19,
  p521_firesaber = 0x2F20,
  p256_kyber512 = 0x2F29,
  p384_kyber768 = 0x2F2A,
  p521_kyber1024 = 0x2F2B,

  /*fzhang:keep line with openssl_oqs*/

  /*defined by fzhang*/
  akcn = 0x2FF0,
  akcn_hybrid = 0x2FF1
  /*defined by fzhang*/
};

std::string toString(NamedGroup);

struct Alert : EventType<Event::Alert> {
  uint8_t level = 0x02;
  AlertDescription description;

  Alert() = default;
  explicit Alert(AlertDescription desc) : description(desc) {}
};

struct CloseNotify : EventType<Event::CloseNotify> {
  CloseNotify() = default;
  explicit CloseNotify(std::unique_ptr<folly::IOBuf> data)
      : ignoredPostCloseData(std::move(data)) {}
  std::unique_ptr<folly::IOBuf> ignoredPostCloseData;
};

class FizzException : public std::runtime_error {
 public:
  FizzException(const std::string& msg, folly::Optional<AlertDescription> alert)
      : std::runtime_error(msg), alert_(alert) {}

  folly::Optional<AlertDescription> getAlert() const {
    return alert_;
  }

 private:
  folly::Optional<AlertDescription> alert_;
};

template <class T>
Buf encode(T&& t);
template <class T>
Buf encodeHandshake(T&& t);
template <class T>
T decode(std::unique_ptr<folly::IOBuf>&& buf);
template <class T>
T decode(folly::io::Cursor& cursor);
template <typename T>
std::string enumToHex(T enumValue);

Buf encodeHkdfLabel(HkdfLabel&& label, const std::string& hkdfLabelPrefix);
} // namespace fizz

#include <fizz/record/Types-inl.h>
