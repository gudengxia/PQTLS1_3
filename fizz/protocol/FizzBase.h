/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/Factory.h>
#include <fizz/protocol/Params.h>
#include <fizz/util/Variant.h>

namespace fizz {

/**
 * FizzBase defines an async method of communicating with the fizz state
 * machine. Given a const reference to state, and a reference to
 * transportReadBuf, FizzBase will consume the transportReadBuf and process
 * events as applicable. visitor is variant visitor that is expected to process
 * Actions as they are received. A DestructorGuard on owner will be taken when
 * async actions are in flight, during which time this class must not be
 * deleted.
 */
template <typename Derived, typename ActionMoveVisitor, typename StateMachine>
class FizzBase {
 public:
  FizzBase(
      const typename StateMachine::StateType& state,
      folly::IOBufQueue& transportReadBuf,
      ActionMoveVisitor& visitor,
      folly::DelayedDestructionBase* owner)
      : state_(state),
        transportReadBuf_(transportReadBuf),
        visitor_(visitor),
        owner_(owner) {}
  virtual ~FizzBase() = default;

  /**
   * Server only: Called to write new session ticket to client.
   */
  void writeNewSessionTicket(WriteNewSessionTicket writeNewSessionTicket);

  /**
   * Called to write application data.
   */
  void appWrite(AppWrite appWrite);

  /**
   * Called to write early application data.
   */
  void earlyAppWrite(EarlyAppWrite appWrite);

  /**
   * Called when the application wants to close the connection, and wait for
   * the corresponding peer's acknowledgement.
   */
  void appClose();

  /**
   * Called when the application wants to immediately close the connection
   * without waiting for the corresponding peer's acknowledgement.
   */
  void appCloseImmediate();

  /**
   * Called to pause processing of transportReadBuf until new data is available.
   *
   * Call newTransportData() to resume processing.
   */
  void waitForData();

  /**
   * Called to notify that new transport data is available in transportReadBuf.
   */
  void newTransportData();

  /**
   * Calls error callbacks on any pending events and prevents any further events
   * from being processed. Should be called when an error is received from
   * either the state machine or the transport that will cause the connection to
   * abort. Note that this does not stop a currently processing event.
   */
  void moveToErrorState(const folly::AsyncSocketException& ex);

  /**
   * Returns true if in error state where no further events will be processed.
   */
  bool inErrorState() const;

  /**
   * Returns true if in a terminal state where no further events will be
   * processed.
   */
  bool inTerminalState() const;

  /**
   * Returns true if the state machine is actively processing an event or
   * action.
   */
  bool actionProcessing() const;

  /**
   * Returns an exported key material derived from the 1-RTT secret of the TLS
   * connection.
   */
  Buf getEkm(
      const Factory& factory,
      folly::StringPiece label,
      const Buf& context,
      uint16_t length) const;

 protected:
  void processActions(typename StateMachine::CompletedActions actions);

  void addProcessingActions(typename StateMachine::ProcessingActions actions);

  virtual void visitActions(
      typename StateMachine::CompletedActions& actions) = 0;

  StateMachine machine_;
  const typename StateMachine::StateType& state_;
  folly::IOBufQueue& transportReadBuf_;

  ActionMoveVisitor& visitor_;

 private:
  void processPendingEvents();

  folly::DelayedDestructionBase* owner_;

#define FIZZ_PENDING_EVENT(F, ...) \
  F(AppWrite, __VA_ARGS__)         \
  F(EarlyAppWrite, __VA_ARGS__)    \
  F(AppClose, __VA_ARGS__)         \
  F(WriteNewSessionTicket, __VA_ARGS__)

  FIZZ_DECLARE_VARIANT_TYPE(PendingEvent, FIZZ_PENDING_EVENT)

  std::deque<PendingEvent> pendingEvents_;
  bool waitForData_{true};
  folly::Optional<folly::DelayedDestruction::DestructorGuard> actionGuard_;
  bool inProcessPendingEvents_{false};
  bool externalError_{false};
};
} // namespace fizz

#include <fizz/protocol/FizzBase-inl.h>
