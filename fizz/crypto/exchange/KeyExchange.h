/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Range.h>
#include <folly/io/IOBuf.h>

namespace fizz {

/**
 * Interface for key exchange algorithms.
 */
class KeyExchange {
 public:
  virtual ~KeyExchange() = default;

  virtual void setServer(bool is = false){} //fzhang
  /**
   * Generates an ephemeral key pair.
   */
  virtual void generateKeyPair() = 0;

  /**
   * Returns the public key to share with peers.
   *
   * generateKeyPair() must be called before.
   */
  virtual std::unique_ptr<folly::IOBuf> getKeyShare() const = 0;

  /**
   * Generate a shared secret with our key pair and a peer's public key share.
   *
   * Performs all necessary validation of the public key share and throws on
   * error.
   *
   * generateKeyPair() must be called before.
   */
  virtual std::unique_ptr<folly::IOBuf> generateSharedSecret(
      folly::ByteRange keyShare) = 0; //fzhang remove const
};
} // namespace fizz
