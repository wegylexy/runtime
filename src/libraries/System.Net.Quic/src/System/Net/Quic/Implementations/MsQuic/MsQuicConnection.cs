// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Net.Quic.Implementations.MsQuic.Internal;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;
using static System.Net.Quic.Implementations.MsQuic.Internal.MsQuicNativeMethods;

namespace System.Net.Quic.Implementations.MsQuic
{
    internal sealed class MsQuicConnection : QuicConnectionProvider
    {
        // Delegate that wraps the static function that will be called when receiving an event.
        private static readonly ConnectionCallbackDelegate s_connectionDelegate = new ConnectionCallbackDelegate(NativeCallbackHandler);

        // TODO: remove this.
        // This is only used for client-initiated connections, and isn't needed even then once Connect() has been called.
        private readonly SafeMsQuicConfigurationHandle? _configuration;

        private readonly State _state = new State();
        private GCHandle _stateHandle;
        private bool _disposed;

        private IPEndPoint? _localEndPoint;
        private readonly EndPoint _remoteEndPoint;
        private SslApplicationProtocol _negotiatedAlpnProtocol;

        private sealed class State
        {
            public SafeMsQuicConnectionHandle Handle = null!; // set inside of MsQuicConnection ctor.

            // These exists to prevent GC of the MsQuicConnection in the middle of an async op (Connect or Shutdown).
            public MsQuicConnection? Connection;

            // TODO: only allocate these when there is an outstanding connect/shutdown.
            public readonly TaskCompletionSource<uint> ConnectTcs = new TaskCompletionSource<uint>(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly TaskCompletionSource<uint> ShutdownTcs = new TaskCompletionSource<uint>(TaskCreationOptions.RunContinuationsAsynchronously);

            public IPEndPoint? LocalEndPoint;
            public bool Connected;
            public long AbortErrorCode = -1;
            public ushort DatagramMaxSendLength;

            // Queue for accepted streams.
            // Backlog limit is managed by MsQuic so it can be unbounded here.
            public readonly Channel<MsQuicStream> AcceptQueue = Channel.CreateUnbounded<MsQuicStream>(new UnboundedChannelOptions()
            {
                SingleReader = true,
                SingleWriter = true,
            });
        }

        // constructor for inbound connections
        public MsQuicConnection(IPEndPoint localEndPoint, IPEndPoint remoteEndPoint, SafeMsQuicConnectionHandle handle)
        {
            _state.Handle = handle;
            _state.Connected = true;
            _localEndPoint = localEndPoint;
            _remoteEndPoint = remoteEndPoint;

            _stateHandle = GCHandle.Alloc(_state);
            try
            {
                MsQuicApi.Api.SetCallbackHandlerDelegate(
                    _state.Handle,
                    s_connectionDelegate,
                    GCHandle.ToIntPtr(_stateHandle));
            }
            catch
            {
                _stateHandle.Free();
                throw;
            }
        }

        // constructor for outbound connections
        public MsQuicConnection(QuicClientConnectionOptions options)
        {
            _remoteEndPoint = options.RemoteEndPoint!;
            _configuration = SafeMsQuicConfigurationHandle.Create(options);

            _stateHandle = GCHandle.Alloc(_state);
            try
            {
                // this handle is ref counted by MsQuic, so safe to dispose here.
                using SafeMsQuicConfigurationHandle config = SafeMsQuicConfigurationHandle.Create(options);

                uint status = MsQuicApi.Api.ConnectionOpenDelegate(
                    MsQuicApi.Api.Registration,
                    s_connectionDelegate,
                    GCHandle.ToIntPtr(_stateHandle),
                    out _state.Handle);

                QuicExceptionHelpers.ThrowIfFailed(status, "Could not open the connection.");
            }
            catch
            {
                _stateHandle.Free();
                throw;
            }
        }

        internal override IPEndPoint LocalEndPoint =>
            new IPEndPoint(_localEndPoint!.Address, _localEndPoint!.Port);

        internal override EndPoint RemoteEndPoint => _remoteEndPoint;

        internal override SslApplicationProtocol NegotiatedApplicationProtocol => _negotiatedAlpnProtocol;

        internal override bool Connected => _state.Connected;

        private static uint HandleEventConnected(State state, ref ConnectionEvent connectionEvent)
        {
            if (!state.Connected)
            {
                // Connected will already be true for connections accepted from a listener.

                SOCKADDR_INET inetAddress = MsQuicParameterHelpers.GetINetParam(MsQuicApi.Api, state.Handle, (uint)QUIC_PARAM_LEVEL.CONNECTION, (uint)QUIC_PARAM_CONN.LOCAL_ADDRESS);
                state.LocalEndPoint = MsQuicAddressHelpers.INetToIPEndPoint(ref inetAddress);

                Debug.Assert(state.Connection != null);
                state.Connection.SetNegotiatedAlpn(connectionEvent.Data.Connected.NegotiatedAlpn, connectionEvent.Data.Connected.NegotiatedAlpnLength);
                state.Connection = null;

                state.Connected = true;
                state.ConnectTcs.SetResult(MsQuicStatusCodes.Success);
            }

            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventShutdownInitiatedByTransport(State state, ref ConnectionEvent connectionEvent)
        {
            if (!state.Connected)
            {
                Debug.Assert(state.Connection != null);
                state.Connection = null;

                uint hresult = connectionEvent.Data.ShutdownInitiatedByTransport.Status;
                Exception ex = QuicExceptionHelpers.CreateExceptionForHResult(hresult, "Connection has been shutdown by transport.");
                state.ConnectTcs.SetException(ExceptionDispatchInfo.SetCurrentStackTrace(ex));
            }

            state.AcceptQueue.Writer.Complete();
            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventShutdownInitiatedByPeer(State state, ref ConnectionEvent connectionEvent)
        {
            state.AbortErrorCode = connectionEvent.Data.ShutdownInitiatedByPeer.ErrorCode;
            state.AcceptQueue.Writer.Complete();
            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventShutdownComplete(State state, ref ConnectionEvent connectionEvent)
        {
            state.Connection = null;

            state.ShutdownTcs.SetResult(MsQuicStatusCodes.Success);
            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventNewStream(State state, ref ConnectionEvent connectionEvent)
        {
            var streamHandle = new SafeMsQuicStreamHandle(connectionEvent.Data.StreamStarted.Stream);
            var stream = new MsQuicStream(streamHandle, connectionEvent.StreamFlags);

            state.AcceptQueue.Writer.TryWrite(stream);
            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventStreamsAvailable(State state, ref ConnectionEvent connectionEvent)
        {
            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventDatagramStateChanged(State state, ref ConnectionEvent connectionEvent)
        {
            state.DatagramMaxSendLength = connectionEvent.Data.DatagramStateChanged.MaxSendLength;
            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventDatagramReceived(State state, ref ConnectionEvent connectionEvent)
        {
            state.Connection!.DatagramReceived?.Invoke(state.Connection, connectionEvent.DatagramReceivedBuffer);
            return MsQuicStatusCodes.Success;
        }

        private static uint HandleEventDatagramSendStateChanged(State state, ref ConnectionEvent connectionEvent)
        {
            var datagramState = connectionEvent.Data.DatagramSendStateChanged.State;
            GCHandle handle = GCHandle.FromIntPtr(connectionEvent.Data.DatagramSendStateChanged.ClientContext);
            var source = (SendDatagramValueTaskSource)handle.Target!;
            switch (datagramState)
            {
                case QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_LOST_DISCARDED:
                case QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_ACKNOWLEDGED:
                case QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS:
                case QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_CANCELED:
                    source.SetResult(datagramState);
                    break;
                default:
                    break;
            }
            return MsQuicStatusCodes.Success;
        }

        internal override async ValueTask<QuicStreamProvider> AcceptStreamAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            MsQuicStream stream;

            try
            {
                stream = await _state.AcceptQueue.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException)
            {
                throw _state.AbortErrorCode switch
                {
                    -1 => new QuicOperationAbortedException(), // Shutdown initiated by us.
                    long err => new QuicConnectionAbortedException(err) // Shutdown initiated by peer.
                };
            }

            return stream;
        }

        internal override QuicStreamProvider OpenUnidirectionalStream()
        {
            ThrowIfDisposed();
            return new MsQuicStream(_state.Handle, QUIC_STREAM_OPEN_FLAG.UNIDIRECTIONAL);
        }

        internal override QuicStreamProvider OpenBidirectionalStream()
        {
            ThrowIfDisposed();
            return new MsQuicStream(_state.Handle, QUIC_STREAM_OPEN_FLAG.NONE);
        }

        internal override long GetRemoteAvailableUnidirectionalStreamCount()
        {
            return MsQuicParameterHelpers.GetUShortParam(MsQuicApi.Api, _state.Handle, (uint)QUIC_PARAM_LEVEL.CONNECTION, (uint)QUIC_PARAM_CONN.LOCAL_UNIDI_STREAM_COUNT);
        }

        internal override long GetRemoteAvailableBidirectionalStreamCount()
        {
            return MsQuicParameterHelpers.GetUShortParam(MsQuicApi.Api, _state.Handle, (uint)QUIC_PARAM_LEVEL.CONNECTION, (uint)QUIC_PARAM_CONN.LOCAL_BIDI_STREAM_COUNT);
        }

        internal override ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (_configuration is null)
            {
                throw new Exception($"{nameof(ConnectAsync)} must not be called on a connection obtained from a listener.");
            }

            (string address, int port) = _remoteEndPoint switch
            {
                DnsEndPoint dnsEp => (dnsEp.Host, dnsEp.Port),
                IPEndPoint ipEp => (ipEp.Address.ToString(), ipEp.Port),
                _ => throw new Exception($"Unsupported remote endpoint type '{_remoteEndPoint.GetType()}'.")
            };

            // TODO: MsQuic will use system constants, so we should use the Socket PAL to translate these.
            int af = _remoteEndPoint.AddressFamily switch
            {
                AddressFamily.Unspecified => 0,
                AddressFamily.InterNetwork => 2,
                AddressFamily.InterNetworkV6 => 23,
                _ => throw new Exception(SR.Format(SR.net_quic_unsupported_address_family, _remoteEndPoint.AddressFamily))
            };

            _state.Connection = this;
            try
            {
                uint status = MsQuicApi.Api.ConnectionStartDelegate(
                    _state.Handle,
                    _configuration,
                    (ushort)af,
                    address,
                    (ushort)port);

                QuicExceptionHelpers.ThrowIfFailed(status, "Failed to connect to peer.");
            }
            catch
            {
                _state.Connection = null;
                throw;
            }

            return new ValueTask(_state.ConnectTcs.Task);
        }

        private ValueTask ShutdownAsync(
            QUIC_CONNECTION_SHUTDOWN_FLAG Flags,
            long ErrorCode)
        {
            Debug.Assert(!_state.ShutdownTcs.Task.IsCompleted);

            // Store the connection into the GCHandle'd state to prevent GC if user calls ShutdownAsync and gets rid of all references to the MsQuicConnection.
            Debug.Assert(_state.Connection == null);
            _state.Connection = this;

            try
            {
                MsQuicApi.Api.ConnectionShutdownDelegate(
                    _state.Handle,
                    (uint)Flags,
                    ErrorCode);
            }
            catch
            {
                _state.Connection = null;
                throw;
            }

            return new ValueTask(_state.ShutdownTcs.Task);
        }

        internal void SetNegotiatedAlpn(IntPtr alpn, int alpnLength)
        {
            if (alpn != IntPtr.Zero && alpnLength != 0)
            {
                var buffer = new byte[alpnLength];
                Marshal.Copy(alpn, buffer, 0, alpnLength);
                _negotiatedAlpnProtocol = new SslApplicationProtocol(buffer);
            }
        }

        private static uint NativeCallbackHandler(
            IntPtr connection,
            IntPtr context,
            ref ConnectionEvent connectionEvent)
        {
            var state = (State)GCHandle.FromIntPtr(context).Target!;

            try
            {
                switch ((QUIC_CONNECTION_EVENT)connectionEvent.Type)
                {
                    case QUIC_CONNECTION_EVENT.CONNECTED:
                        return HandleEventConnected(state, ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.SHUTDOWN_INITIATED_BY_TRANSPORT:
                        return HandleEventShutdownInitiatedByTransport(state, ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.SHUTDOWN_INITIATED_BY_PEER:
                        return HandleEventShutdownInitiatedByPeer(state, ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.SHUTDOWN_COMPLETE:
                        return HandleEventShutdownComplete(state, ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.PEER_STREAM_STARTED:
                        return HandleEventNewStream(state, ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.STREAMS_AVAILABLE:
                        return HandleEventStreamsAvailable(state, ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.DATAGRAM_STATE_CHANGED:
                        return HandleEventDatagramStateChanged(ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.DATAGRAM_RECEIVED:
                        return HandleEventDatagramReceived(ref connectionEvent);
                    case QUIC_CONNECTION_EVENT.DATAGRAM_SEND_STATE_CHANGED:
                        return HandleEventDatagramSendStateChanged(ref connectionEvent);
                    default:
                        return MsQuicStatusCodes.Success;
                }
            }
            catch (Exception ex)
            {
                if (NetEventSource.Log.IsEnabled())
                {
                    NetEventSource.Error(state, $"Exception occurred during connection callback: {ex.Message}");
                }

                // TODO: trigger an exception on any outstanding async calls.

                return MsQuicStatusCodes.InternalError;
            }
        }

        public override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~MsQuicConnection()
        {
            Dispose(false);
        }

        private void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            _state.Handle.Dispose();
            if (_stateHandle.IsAllocated) _stateHandle.Free();
            _disposed = true;
        }

        // TODO: this appears abortive and will cause prior successfully shutdown and closed streams to drop data.
        // It's unclear how to gracefully wait for a connection to be 100% done.
        internal override ValueTask CloseAsync(long errorCode, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return ShutdownAsync(QUIC_CONNECTION_SHUTDOWN_FLAG.NONE, errorCode);
        }

        internal override bool DatagramReceiveEnabled
        {
            get => MsQuicParameterHelpers.GetByteParam(MsQuicApi.Api, _state.Handle, (uint)QUIC_PARAM_LEVEL.CONNECTION, (uint)QUIC_PARAM_CONN.DATAGRAM_RECEIVE_ENABLED) != 0;
            set => MsQuicParameterHelpers.SetByteParam(MsQuicApi.Api, _state.Handle, (uint)QUIC_PARAM_LEVEL.CONNECTION, (uint)QUIC_PARAM_CONN.DATAGRAM_RECEIVE_ENABLED, (byte)(value ? 1 : 0));
        }

        internal override bool DatagramSendEnabled
        {
            get => MsQuicParameterHelpers.GetByteParam(MsQuicApi.Api, _state.Handle, (uint)QUIC_PARAM_LEVEL.CONNECTION, (uint)QUIC_PARAM_CONN.DATAGRAM_SEND_ENABLED) != 0;
            set => MsQuicParameterHelpers.SetByteParam(MsQuicApi.Api, _state.Handle, (uint)QUIC_PARAM_LEVEL.CONNECTION, (uint)QUIC_PARAM_CONN.DATAGRAM_SEND_ENABLED, (byte)(value ? 1 : 0));
        }

        internal override ushort DatagramMaxSendLength => _state.DatagramMaxSendLength;

        internal override event QuicDatagramReceivedEventHandler? DatagramReceived;

        class SendDatagramValueTaskSource : IValueTaskSource<QUIC_DATAGRAM_SEND_STATE>
        {
            ManualResetValueTaskSourceCore<QUIC_DATAGRAM_SEND_STATE> _source;

            public SendDatagramValueTaskSource(ManualResetValueTaskSourceCore<QUIC_DATAGRAM_SEND_STATE> source) => _source = source;

            public QUIC_DATAGRAM_SEND_STATE GetResult(short token) => _source.GetResult(token);

            public ValueTaskSourceStatus GetStatus(short token) => _source.GetStatus(token);

            public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) => _source.OnCompleted(continuation, state, token, flags);

            public short Version => _source.Version;

            public void SetResult(QUIC_DATAGRAM_SEND_STATE result) => _source.SetResult(result);
        }

        internal override async ValueTask<bool> SendDatagramAsync(ReadOnlyMemory<byte> buffer, bool priority)
        {
            SendDatagramValueTaskSource source = new(new());
            var sourceHandle = GCHandle.Alloc(source, GCHandleType.Pinned);
            using var handle = buffer.Pin();
            var quicBuffer = new QuicBuffer[1];
            quicBuffer[0].Length = (uint)buffer.Length;
            unsafe { quicBuffer[0].Buffer = (byte*)handle.Pointer; }
            var quicBufferHandle = GCHandle.Alloc(quicBuffer, GCHandleType.Pinned);
            try
            {
                unsafe
                {
                    var status = MsQuicApi.Api.DatagramSendDelegate(
                        _state.Handle,
                        (QuicBuffer*)Marshal.UnsafeAddrOfPinnedArrayElement(quicBuffer, 0),
                        1,
                        (uint)(priority ? QUIC_SEND_FLAG.DGRAM_PRIORITY : QUIC_SEND_FLAG.NONE),
                        sourceHandle.AddrOfPinnedObject());
                    QuicExceptionHelpers.ThrowIfFailed(status, "Failed to send a datagram to peer.");
                }
                return (await new ValueTask<QUIC_DATAGRAM_SEND_STATE>(source, source.Version)) switch
                {
                    QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_ACKNOWLEDGED => true,
                    QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS => false,
                    QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_CANCELED => throw new OperationCanceledException("Datagram send canceled."),
                    QUIC_DATAGRAM_SEND_STATE.QUIC_DATAGRAM_SEND_LOST_DISCARDED => throw new QuicException("Datagram lost discarded."),
                    _ => throw new QuicException("Unknown datagram send state.")
                };
            }
            finally
            {
                quicBufferHandle.Free();
                sourceHandle.Free();
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(MsQuicStream));
            }
        }
    }
}
