/*
 * Copyright 2017 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <memory>

#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncSocketBase.h>
#include <folly/io/async/DelayedDestruction.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/ssl/OpenSSLPtrTypes.h>
#include <folly/portability/SysUio.h>

#include <openssl/ssl.h>

constexpr bool kOpenSslModeMoveBufferOwnership =
#ifdef SSL_MODE_MOVE_BUFFER_OWNERSHIP
  true
#else
  false
#endif
  ;

namespace folly {

class AsyncSocketException;
class EventBase;
class SocketAddress;

/*
 * flags given by the application for write* calls
 */
enum class WriteFlags : uint32_t {
  NONE = 0x00,
  /*
   * Whether to delay the output until a subsequent non-corked write.
   * (Note: may not be supported in all subclasses or on all platforms.)
   */
  CORK = 0x01,
  /*
   * for a socket that has ACK latency enabled, it will cause the kernel
   * to fire a TCP ESTATS event when the last byte of the given write call
   * will be acknowledged.
   */
  EOR = 0x02,
  /*
   * this indicates that only the write side of socket should be shutdown
   */
  WRITE_SHUTDOWN = 0x04,
};

/*
 * union operator
 */
inline WriteFlags operator|(WriteFlags a, WriteFlags b) {
  return static_cast<WriteFlags>(
           static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/*
 * compound assignment union operator
 */
inline WriteFlags& operator|=(WriteFlags& a, WriteFlags b) {
  a = a | b;
  return a;
}

/*
 * intersection operator
 */
inline WriteFlags operator&(WriteFlags a, WriteFlags b) {
  return static_cast<WriteFlags>(
           static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/*
 * compound assignment intersection operator
 */
inline WriteFlags& operator&=(WriteFlags& a, WriteFlags b) {
  a = a & b;
  return a;
}

/*
 * exclusion parameter
 */
inline WriteFlags operator~(WriteFlags a) {
  return static_cast<WriteFlags>(~static_cast<uint32_t>(a));
}

/*
 * unset operator
 */
inline WriteFlags unSet(WriteFlags a, WriteFlags b) {
  return a & ~b;
}

/*
 * inclusion operator
 */
inline bool isSet(WriteFlags a, WriteFlags b) {
  return (a & b) == b;
}


/**
  AsyncTransport为I/O流定义了一个异步API。

  这个类提供了一个API来在流传输上异步等待数据，以及用于异步发送数据。

  用于读取和写入的API是有意不对称的。 等待要读取的数据是一个持久性API：已安装的回调，
   每当有新数据可用时被通知， 它继续被通知新事件直到它被卸载。

  AsyncTransport不提供读超时功能，因为它通常无法确定何时应该启用超时。 一般来说，一个超时
  应该仅在处理等待数据被远程端点阻止时启用。对于服务器端应用程序，超时不应该被启用，如果服务器当前正
  在处理一个或多个未完成的请求。 对于客户端应用程序，超时不应该被激活，如果在传输上没有有待处理的请求。
  此外，如果客户端有多个挂起的请求，它将通常需要为每个请求单独设置超时，而不是单个读取超时。

  写API是相当直观的：用户可以请求发送一个块数据，并且一旦整个块已经被传输到内核或者出错就将通知回调
   。AsyncTransport提供了一个发送超时，因为如果远程端停止并且不能进一步发送数据，大多数调用者想要放弃，。
 */
class AsyncTransport : public DelayedDestruction, public AsyncSocketBase {
public:
  typedef std::unique_ptr<AsyncTransport, Destructor> UniquePtr;

  /**
   * Close the transport.
   *
   * This gracefully closes the transport, waiting for all pending write
   * requests to complete before actually closing the underlying transport.
   *
   * If a read callback is set, readEOF() will be called immediately.  If there
   * are outstanding write requests, the close will be delayed until all
   * remaining writes have completed.  No new writes may be started after
   * close() has been called.
   */
  virtual void close() = 0;

  /**
   * Close the transport immediately.
   *
   * This closes the transport immediately, dropping any outstanding data
   * waiting to be written.
   *
   * If a read callback is set, readEOF() will be called immediately.
   * If there are outstanding write requests, these requests will be aborted
   * and writeError() will be invoked immediately on all outstanding write
   * callbacks.
   */
  virtual void closeNow() = 0;

  /**
   * Reset the transport immediately.
   *
   * This closes the transport immediately, sending a reset to the remote peer
   * if possible to indicate abnormal shutdown.
   *
   * Note that not all subclasses implement this reset functionality: some
   * subclasses may treat reset() the same as closeNow().  Subclasses that use
   * TCP transports should terminate the connection with a TCP reset.
   */
  virtual void closeWithReset() {
    closeNow();
  }

  /**
   * Perform a half-shutdown of the write side of the transport.
   *
   * The caller should not make any more calls to write() or writev() after
   * shutdownWrite() is called.  Any future write attempts will fail
   * immediately.
   *
   * Not all transport types support half-shutdown.  If the underlying
   * transport does not support half-shutdown, it will fully shutdown both the
   * read and write sides of the transport.  (Fully shutting down the socket is
   * better than doing nothing at all, since the caller may rely on the
   * shutdownWrite() call to notify the other end of the connection that no
   * more data can be read.)
   *
   * If there is pending data still waiting to be written on the transport,
   * the actual shutdown will be delayed until the pending data has been
   * written.
   *
   * Note: There is no corresponding shutdownRead() equivalent.  Simply
   * uninstall the read callback if you wish to stop reading.  (On TCP sockets
   * at least, shutting down the read side of the socket is a no-op anyway.)
   */
  virtual void shutdownWrite() = 0;

  /**
   * Perform a half-shutdown of the write side of the transport.
   *
   * shutdownWriteNow() is identical to shutdownWrite(), except that it
   * immediately performs the shutdown, rather than waiting for pending writes
   * to complete.  Any pending write requests will be immediately failed when
   * shutdownWriteNow() is called.
   */
  virtual void shutdownWriteNow() = 0;

  /**
   * Determine if transport is open and ready to read or write.
   *
   * Note that this function returns false on EOF; you must also call error()
   * to distinguish between an EOF and an error.
   *
   * @return  true iff the transport is open and ready, false otherwise.
   */
  virtual bool good() const = 0;

  /**
   * Determine if the transport is readable or not.
   *
   * @return  true iff the transport is readable, false otherwise.
   */
  virtual bool readable() const = 0;

  /**
   * Determine if the there is pending data on the transport.
   *
   * @return  true iff the if the there is pending data, false otherwise.
   */
  virtual bool isPending() const {
    return readable();
  }

  /**
   * Determine if transport is connected to the endpoint
   *
   * @return  false iff the transport is connected, otherwise true
   */
  virtual bool connecting() const = 0;

  /**
   * Determine if an error has occurred with this transport.
   *
   * @return  true iff an error has occurred (not EOF).
   */
  virtual bool error() const = 0;

  /**
   * Attach the transport to a EventBase.
   *
   * This may only be called if the transport is not currently attached to a
   * EventBase (by an earlier call to detachEventBase()).
   *
   * This method must be invoked in the EventBase's thread.
   */
  virtual void attachEventBase(EventBase* eventBase) = 0;

  /**
   * Detach the transport from its EventBase.
   *
   * This may only be called when the transport is idle and has no reads or
   * writes pending.  Once detached, the transport may not be used again until
   * it is re-attached to a EventBase by calling attachEventBase().
   *
   * This method must be called from the current EventBase's thread.
   */
  virtual void detachEventBase() = 0;

  /**
   * Determine if the transport can be detached.
   *
   * This method must be called from the current EventBase's thread.
   */
  virtual bool isDetachable() const = 0;

  /**
   * Set the send timeout.
   *
   * If write requests do not make any progress for more than the specified
   * number of milliseconds, fail all pending writes and close the transport.
   *
   * If write requests are currently pending when setSendTimeout() is called,
   * the timeout interval is immediately restarted using the new value.
   *
   * @param milliseconds  The timeout duration, in milliseconds.  If 0, no
   *                      timeout will be used.
   */
  virtual void setSendTimeout(uint32_t milliseconds) = 0;

  /**
   * Get the send timeout.
   *
   * @return Returns the current send timeout, in milliseconds.  A return value
   *         of 0 indicates that no timeout is set.
   */
  virtual uint32_t getSendTimeout() const = 0;

  /**
   * Get the address of the local endpoint of this transport.
   *
   * This function may throw AsyncSocketException on error.
   *
   * @param address  The local address will be stored in the specified
   *                 SocketAddress.
   */
  virtual void getLocalAddress(SocketAddress* address) const = 0;

  virtual void getAddress(SocketAddress* address) const {
    getLocalAddress(address);
  }

  /**
   * Get the address of the remote endpoint to which this transport is
   * connected.
   *
   * This function may throw AsyncSocketException on error.
   *
   * @param address  The remote endpoint's address will be stored in the
   *                 specified SocketAddress.
   */
  virtual void getPeerAddress(SocketAddress* address) const = 0;

  /**
   * Get the certificate used to authenticate the peer.
   */
  virtual ssl::X509UniquePtr getPeerCert() const { return nullptr; }

  /**
   * The local certificate used for this connection. May be null
   */
  virtual const X509* getSelfCert() const {
    return nullptr;
  }

  /**
   * @return True iff end of record tracking is enabled
   */
  virtual bool isEorTrackingEnabled() const = 0;

  virtual void setEorTracking(bool track) = 0;

  virtual size_t getAppBytesWritten() const = 0;
  virtual size_t getRawBytesWritten() const = 0;
  virtual size_t getAppBytesReceived() const = 0;
  virtual size_t getRawBytesReceived() const = 0;

  class BufferCallback {
  public:
    virtual ~BufferCallback() {}
    virtual void onEgressBuffered() = 0;
    virtual void onEgressBufferCleared() = 0;
  };

  /**
   * Callback class to signal when a transport that did not have replay
   * protection gains replay protection. This is needed for 0-RTT security
   * protocols.
   */
  class ReplaySafetyCallback {
  public:
    virtual ~ReplaySafetyCallback() = default;

    /**
     * Called when the transport becomes replay safe.
     */
    virtual void onReplaySafe() = 0;
  };

  /**
   * False if the transport does not have replay protection, but will in the
   * future.
   */
  virtual bool isReplaySafe() const { return true; }

  /**
   * Set the ReplaySafeCallback on this transport.
   *
   * This should only be called if isReplaySafe() returns false.
   */
  virtual void setReplaySafetyCallback(ReplaySafetyCallback* callback) {
    if (callback) {
      CHECK(false) << "setReplaySafetyCallback() not supported";
    }
  }

protected:
  virtual ~AsyncTransport() = default;
};

class AsyncReader {
public:
  class ReadCallback {
  public:
    virtual ~ReadCallback() = default;

    /**
      当数据变得可用时，getReadBuffer（）将被调用来获取缓冲器，用来存放读取数据。

      此方法允许ReadCallback延迟缓冲区分配，直到数据可用。 这允许应用程序管理大
          空闲连接的数量，而不必为每个空闲连接保持单独的读取缓冲区。

      在某些情况下，在readDataAvailable（）被调用之前getReadBuffer（）可能会调用多次。 在这种情况下，
      数据将被写入从最近一次调用返回的缓冲区。 如果以前调用getReadBuffer（）返回不同的缓冲区，
      ReadCallback负责确保他们不泄漏。


      If getReadBuffer() throws an exception, returns a nullptr buffer, or
      returns a 0 length, the ReadCallback will be uninstalled and its
      readError() method will be invoked.

      getReadBuffer() is not allowed to change the transport state before it
      returns.  (For example, it should never uninstall the read callback, or
      set a different read callback.)

      @param bufReturn getReadBuffer() should update *bufReturn to contain the
                       address of the read buffer.  This parameter will never
                       be nullptr.
      @param lenReturn getReadBuffer() should update *lenReturn to contain the
                       maximum number of bytes that may be written to the read
                       buffer.  This parameter will never be nullptr.
     */
    virtual void getReadBuffer(void** bufReturn, size_t* lenReturn) = 0;

    /**
      readDataAvailable（）将在数据被成功读取进由最后一次调用getReadBuffer（）返回的缓冲区时被调用。
       readDataAvailable（）返回后，读回调将保持安装。必须明确地卸载它才能停止接收读取事件。
       getReadBuffer（）将在每次调用readDataAvailable（）之前至少被调用一次。
       getReadBuffer（）也将在任何调用readEOF（）之前被调用。

      @param len       The number of bytes placed in the buffer.
     */

    virtual void readDataAvailable(size_t len) noexcept = 0;

    /**
     * When data becomes available, isBufferMovable() will be invoked to figure
     * out which API will be used, readBufferAvailable() or
     * readDataAvailable(). If isBufferMovable() returns true, that means
     * ReadCallback supports the IOBuf ownership transfer and
     * readBufferAvailable() will be used.  Otherwise, not.

     * By default, isBufferMovable() always return false. If
     * readBufferAvailable() is implemented and to be invoked, You should
     * overwrite isBufferMovable() and return true in the inherited class.
     *
     * This method allows the AsyncSocket/AsyncSSLSocket do buffer allocation by
     * itself until data becomes available.  Compared with the pre/post buffer
     * allocation in getReadBuffer()/readDataAvailabe(), readBufferAvailable()
     * has two advantages.  First, this can avoid memcpy. E.g., in
     * AsyncSSLSocket, the decrypted data was copied from the openssl internal
     * buffer to the readbuf buffer.  With the buffer ownership transfer, the
     * internal buffer can be directly "moved" to ReadCallback. Second, the
     * memory allocation can be more precise.  The reason is
     * AsyncSocket/AsyncSSLSocket can allocate the memory of precise size
     * because they have more context about the available data than
     * ReadCallback.  Think about the getReadBuffer() pre-allocate 4072 bytes
     * buffer, but the available data is always 16KB (max OpenSSL record size).
     */

    virtual bool isBufferMovable() noexcept {
      return false;
    }

    /**
     * Suggested buffer size, allocated for read operations,
     * if callback is movable and supports folly::IOBuf
     */

    virtual size_t maxBufferSize() const {
      return 64 * 1024; // 64K
    }

    /**
     * readBufferAvailable() will be invoked when data has been successfully
     * read.
     *
     * Note that only either readBufferAvailable() or readDataAvailable() will
     * be invoked according to the return value of isBufferMovable(). The timing
     * and aftereffect of readBufferAvailable() are the same as
     * readDataAvailable()
     *
     * @param readBuf The unique pointer of read buffer.
     */

    virtual void readBufferAvailable(std::unique_ptr<IOBuf> /*readBuf*/)
    noexcept {}

    /**
     * readEOF() will be invoked when the transport is closed.
     *
     * The read callback will be automatically uninstalled immediately before
     * readEOF() is invoked.
     */
    virtual void readEOF() noexcept = 0;

    /**
     * readError() will be invoked if an error occurs reading from the
     * transport.
     *
     * The read callback will be automatically uninstalled immediately before
     * readError() is invoked.
     *
     * @param ex        An exception describing the error that occurred.
     */
    virtual void readErr(const AsyncSocketException& ex) noexcept = 0;
  };

  // Read methods that aren't part of AsyncTransport.
  virtual void setReadCB(ReadCallback* callback) = 0;
  virtual ReadCallback* getReadCallback() const = 0;

protected:
  virtual ~AsyncReader() = default;
};

class AsyncWriter {
public:
  class WriteCallback {
  public:
    virtual ~WriteCallback() = default;

    /**
     * writeSuccess() will be invoked when all of the data has been
     * successfully written.
     *
     * Note that this mainly signals that the buffer containing the data to
     * write is no longer needed and may be freed or re-used.  It does not
     * guarantee that the data has been fully transmitted to the remote
     * endpoint.  For example, on socket-based transports, writeSuccess() only
     * indicates that the data has been given to the kernel for eventual
     * transmission.
     */
    virtual void writeSuccess() noexcept = 0;

    /**
     * writeError() will be invoked if an error occurs writing the data.
     *
     * @param bytesWritten      The number of bytes that were successfull
     * @param ex                An exception describing the error that occurred.
     */
    virtual void writeErr(size_t bytesWritten,
                          const AsyncSocketException& ex) noexcept = 0;
  };

  // Write methods that aren't part of AsyncTransport
  virtual void write(WriteCallback* callback, const void* buf, size_t bytes,
                     WriteFlags flags = WriteFlags::NONE) = 0;
  virtual void writev(WriteCallback* callback, const iovec* vec, size_t count,
                      WriteFlags flags = WriteFlags::NONE) = 0;
  virtual void writeChain(WriteCallback* callback,
                          std::unique_ptr<IOBuf>&& buf,
                          WriteFlags flags = WriteFlags::NONE) = 0;

protected:
  virtual ~AsyncWriter() = default;
};

// Transitional intermediate interface. This is deprecated(废弃).
// Wrapper around folly::AsyncTransport, that includes read/write callbacks
class AsyncTransportWrapper : virtual public AsyncTransport,
  virtual public AsyncReader,
  virtual public AsyncWriter {
public:
  using UniquePtr = std::unique_ptr<AsyncTransportWrapper, Destructor>;

  // Alias for inherited members from AsyncReader and AsyncWriter
  // to keep compatibility.
  using ReadCallback    = AsyncReader::ReadCallback;
  using WriteCallback   = AsyncWriter::WriteCallback;
  virtual void setReadCB(ReadCallback* callback) override = 0;
  virtual ReadCallback* getReadCallback() const override = 0;
  virtual void write(WriteCallback* callback, const void* buf, size_t bytes,
                     WriteFlags flags = WriteFlags::NONE) override = 0;
  virtual void writev(WriteCallback* callback, const iovec* vec, size_t count,
                      WriteFlags flags = WriteFlags::NONE) override = 0;
  virtual void writeChain(WriteCallback* callback,
                          std::unique_ptr<IOBuf>&& buf,
                          WriteFlags flags = WriteFlags::NONE) override = 0;
  /**
   * The transport wrapper may wrap another transport. This returns the
   * transport that is wrapped. It returns nullptr if there is no wrapped
   * transport.
   */
  virtual const AsyncTransportWrapper* getWrappedTransport() const {
    return nullptr;
  }

  /**
   * In many cases when we need to set socket properties or otherwise access the
   * underlying transport from a wrapped transport. This method allows access to
   * the derived classes of the underlying transport.
   */
  template <class T>
  const T* getUnderlyingTransport() const {
    const AsyncTransportWrapper* current = this;
    while (current) {
      auto sock = dynamic_cast<const T*>(current);
      if (sock) {
        return sock;
      }
      current = current->getWrappedTransport();
    }
    return nullptr;
  }

  template <class T>
  T* getUnderlyingTransport() {
    return const_cast<T*>(static_cast<const AsyncTransportWrapper*>(this)
                          ->getUnderlyingTransport<T>());
  }

  /**
   * Return the application protocol being used by the underlying transport
   * protocol. This is useful for transports which are used to tunnel other
   * protocols.
   */
  virtual std::string getApplicationProtocol() noexcept {
    return "";
  }

  /**
   * Returns the name of the security protocol being used.
   */
  virtual std::string getSecurityProtocol() const { return ""; }
};

} // folly
