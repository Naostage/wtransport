//! # WebTransport Connection
//!
//! [`Connection`] provides an essential building block for managing WebTransport
//! connections. It allows you to initiate, accept, and control data *streams*, send and receive
//! *datagrams*, monitor connection status, and interact with various aspects of your WebTransport
//! communication.
//!
//! WebTransport exchanges data either via [*streams*](crate#streams) or [*datagrams*](crate#datagrams).
//!
//! ## Streams
//! WebTransport streams provide a lightweight, ordered byte-stream abstraction.
//!
//! There are two fundamental types of streams:
//!  - *Unidirectional* streams carry data in a single direction, from the stream initiator to its peer.
//!  - *Bidirectional* streams allow for data to be sent in both directions.
//!
//! Both server and client endpoints have the capability to create an arbitrary number of streams to
//! operate concurrently.
//!
//! Each stream can be independently cancelled by both side.
//!
//! ### Examples
//! #### Open a stream
//! ```no_run
//! # use anyhow::Result;
//! # async fn foo(connection: wtransport::Connection) -> Result<()> {
//! use wtransport::Connection;
//!
//! // Open a bi-directional stream
//! let (mut send_stream, mut recv_stream) = connection.open_bi().await?.await?;
//!
//! // Send data on the stream
//! send_stream.write_all(b"Hello, wtransport!").await?;
//!
//! // Receive data from the stream
//! let mut buffer = vec![0; 1024];
//! let bytes_read = recv_stream.read(&mut buffer).await?;
//!
//! // Open an uni-directional stream (can only send data)
//! let mut send_stream = connection.open_uni().await?.await?;
//!
//! // Send data on the stream
//! send_stream.write_all(b"Hello, wtransport!").await?;
//! # Ok(())
//! # }
//! ```
//!
//! #### Accept a stream
//! ```no_run
//! # use anyhow::Result;
//! # async fn foo(connection: wtransport::Connection) -> Result<()> {
//! use wtransport::Connection;
//!
//! // Await the peer opens a bi-directional stream
//! let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
//!
//! // Can send and receive data on peer's stream
//! send_stream.write_all(b"Hello, wtransport!").await?;
//! # let mut buffer = vec![0; 1024];
//! let bytes_read = recv_stream.read(&mut buffer).await?;
//!
//! // Await the peer opens an uni-directional stream (can only receive data)
//! let mut recv_stream = connection.accept_uni().await?;
//!
//! // Receive data on the stream
//! let bytes_read = recv_stream.read(&mut buffer).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Datagrams
//! WebTransport datagrams are similar to UDP datagrams but come with an
//! added layer of security through *encryption* and *congestion control*.
//! Datagrams can arrive out of order or might not arrive at all, offering
//! flexibility in data exchange scenarios.
//!
//! Unlike streams, which operate as byte-stream abstractions, WebTransport
//! datagrams act more like messages.
//!
//! ### Examples
//! ```no_run
//! # use anyhow::Result;
//! # async fn foo(connection: wtransport::Connection) -> Result<()> {
//! use wtransport::Connection;
//!
//! // Send datagram message
//! connection.send_datagram(b"Hello, wtransport!")?;
//!
//! // Receive a datagram message
//! let message = connection.receive_datagram().await?;
//! # Ok(())
//! # }
//! ```

use crate::datagram::Datagram;
use crate::driver::utils::varint_w2q;
use crate::driver::Driver;
use crate::error::ConnectionError;
use crate::error::ExportKeyingMaterialError;
use crate::error::SendDatagramError;
use crate::stream::OpeningBiStream;
use crate::stream::OpeningUniStream;
use crate::stream::RecvStream;
use crate::stream::SendStream;
use crate::tls::Certificate;
use crate::tls::CertificateChain;
use crate::tls::HandshakeData;
use crate::SessionId;
use crate::VarInt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use wtransport_proto::capsule::capsules::CloseWebTransportSession;

/// A WebTransport session connection.
///
/// For more details, see the [module documentation](crate::connection).
///
/// May be cloned to obtain another handle to the same connection.
#[derive(Clone, Debug)]
pub struct Connection {
    quic_connection: quinn::Connection,
    driver: Arc<Driver>,
    session_id: SessionId,
}

impl Connection {
    pub(crate) fn new(
        quic_connection: quinn::Connection,
        driver: Driver,
        session_id: SessionId,
    ) -> Self {
        Self {
            quic_connection,
            driver: Arc::new(driver),
            session_id,
        }
    }

    /// Asynchronously accepts a unidirectional stream.
    ///
    /// This method is used to accept incoming unidirectional streams that have been initiated
    /// by the remote peer.
    /// It waits for the next unidirectional stream to be available, then wraps it in a
    /// [`RecvStream`] that can be used to read data from the stream.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    pub async fn accept_uni(&self) -> Result<RecvStream, ConnectionError> {
        let stream = self
            .driver
            .accept_uni(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?
            .into_stream();

        Ok(RecvStream::new(stream))
    }

    /// Asynchronously accepts a bidirectional stream.
    ///
    /// This method is used to accept incoming bidirectional streams that have been initiated
    /// by the remote peer.
    /// It waits for the next bidirectional stream to be available, then wraps it in a
    /// tuple containing a [`SendStream`] for sending data and a [`RecvStream`] for receiving
    /// data on the stream.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let stream = self
            .driver
            .accept_bi(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?
            .into_stream();

        Ok((SendStream::new(stream.0), RecvStream::new(stream.1)))
    }

    /// Asynchronously opens a new unidirectional stream.
    ///
    /// This method is used to initiate the opening of a new unidirectional stream.
    ///
    /// # Asynchronous Behavior
    ///
    /// This method is asynchronous and involves two `await` points:
    ///
    /// 1. The first `await` occurs during the initial phase of opening the stream, which may involve awaiting
    ///    the flow controller. This wait is necessary to ensure proper resource allocation and flow control.
    ///    It is safe to cancel this `await` point if needed.
    ///
    /// 2. The second `await` is internal to the returned [`OpeningUniStream`] object when it is used to initialize
    ///    the WebTransport stream. Cancelling this latter future before it completes may result in the stream
    ///    being closed during initialization.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use wtransport::Connection;
    /// # use anyhow::Result;
    /// # async fn run(connection: Connection) -> Result<()> {
    /// let send_stream = connection.open_uni().await?.await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_uni(&self) -> Result<OpeningUniStream, ConnectionError> {
        self.driver
            .open_uni(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Asynchronously opens a new bidirectional stream.
    ///
    /// This method is used to initiate the opening of a new bidirectional stream.
    ///
    /// # Asynchronous Behavior
    ///
    /// This method is asynchronous and involves two `await` points:
    ///
    /// 1. The first `await` occurs during the initial phase of opening the stream, which may involve awaiting
    ///    the flow controller. This wait is necessary to ensure proper resource allocation and flow control.
    ///    It is safe to cancel this `await` point if needed.
    ///
    /// 2. The second `await` is internal to the returned [`OpeningBiStream`] object when it is used to initialize
    ///    the WebTransport stream. Cancelling this latter future before it completes may result in the stream
    ///    being closed during initialization.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use wtransport::Connection;
    /// # use anyhow::Result;
    /// # async fn run(connection: Connection) -> Result<()> {
    /// let (send_stream, recv_stream) = connection.open_bi().await?.await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_bi(&self) -> Result<OpeningBiStream, ConnectionError> {
        self.driver
            .open_bi(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Asynchronously receives an application datagram from the remote peer.
    ///
    /// This method is used to receive an application datagram sent by the remote
    /// peer over the connection.
    /// It waits for a datagram to become available and returns the received [`Datagram`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use wtransport::Connection;
    /// # use anyhow::Result;
    /// # async fn run(connection: Connection) -> Result<()> {
    /// let datagram = connection.receive_datagram().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn receive_datagram(&self) -> Result<Datagram, ConnectionError> {
        self.driver
            .receive_datagram(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Sends an application datagram to the remote peer.
    ///
    /// This method is used to send an application datagram to the remote peer
    /// over the connection.
    /// The datagram payload is provided as a reference to a slice of bytes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use wtransport::Connection;
    /// # use anyhow::Result;
    /// # async fn run(connection: Connection) -> Result<()> {
    /// connection.send_datagram(b"Hello, wtransport!")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_datagram<D>(&self, payload: D) -> Result<(), SendDatagramError>
    where
        D: AsRef<[u8]>,
    {
        self.driver.send_datagram(self.session_id, payload.as_ref())
    }

    /// Closes the connection immediately.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.quic_connection.close(varint_w2q(error_code), reason);
    }

    /// Closes the WebTransport session with an application `error_code` and `reason`.
    ///
    /// Unlike [`close`](Self::close), the peer receives `error_code` and `reason`
    /// as a WebTransport session close (a `CLOSE_WEBTRANSPORT_SESSION` capsule), which
    /// is what browsers expose as `WebTransportCloseInfo`.
    ///
    /// This sends the capsule and finishes the session's CONNECT stream, then waits up to
    /// 3 seconds for the peer to acknowledge them and to end its side of the stream, before
    /// closing the connection. It returns once the connection is closed. If the connection is
    /// already closed, this sends nothing.
    ///
    /// # Cancel safety
    ///
    /// Once polled, the close goes on even if the returned future is dropped.
    ///
    /// # Panics
    ///
    /// Panics if `reason` is longer than
    /// [`MAX_REASON_LEN`](crate::proto::capsule::capsules::CloseWebTransportSession::MAX_REASON_LEN)
    /// bytes.
    pub async fn close_session(&self, error_code: u32, reason: &str) {
        let close_session = CloseWebTransportSession::new(error_code, reason);
        self.driver.close_session(close_session).await;
    }

    /// Waits for the connection to be closed for any reason.
    ///
    /// If the peer closed the session, with a `CLOSE_WEBTRANSPORT_SESSION` capsule or by
    /// finishing the CONNECT stream, this returns [`ConnectionError::ApplicationClosed`] with the
    /// session's code and reason rather than the QUIC connection close. After
    /// [`close_session`](Self::close_session), it returns [`ConnectionError::LocallyClosed`].
    pub async fn closed(&self) -> ConnectionError {
        let quic_error = self.quic_connection.closed().await;

        match self.driver.terminated().await {
            Some(driver_error) => {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            }
            None => quic_error.into(),
        }
    }

    /// Returns the WebTransport session identifier.
    #[inline(always)]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the peer's UDP address.
    ///
    /// **Note**: as QUIC supports migration, remote address may change
    /// during connection. Furthermore, when IPv6 support is enabled, IPv4
    /// addresses may be mapped to IPv6.
    #[inline(always)]
    pub fn remote_address(&self) -> SocketAddr {
        self.quic_connection.remote_address()
    }

    /// A stable identifier for this connection.
    ///
    /// Peer addresses and connection IDs can change, but this value will remain
    /// fixed for the lifetime of the connection.
    #[inline(always)]
    pub fn stable_id(&self) -> usize {
        self.quic_connection.stable_id()
    }

    /// Computes the maximum size of datagrams that may be passed to
    /// [`send_datagram`](Self::send_datagram).
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    #[inline(always)]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.quic_connection
            .max_datagram_size()
            .map(|quic_max_size| quic_max_size - Datagram::header_size(self.session_id))
    }

    /// Current best estimate of this connection's latency (round-trip-time).
    #[inline(always)]
    pub fn rtt(&self) -> Duration {
        self.quic_connection.rtt()
    }

    /// Derive keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.quic_connection
            .export_keying_material(output, label, context)
            .map_err(|_: quinn::crypto::ExportKeyingMaterialError| ExportKeyingMaterialError)
    }

    /// Returns the peer's identity as a certificate chain if available.
    ///
    /// This function returns an `Option` containing a [`CertificateChain`]. If the peer's identity
    /// is available, it is converted into a `CertificateChain` and returned. If the peer's identity
    /// is not available, `None` is returned.
    pub fn peer_identity(&self) -> Option<CertificateChain> {
        self.quic_connection.peer_identity().map(|any| {
            any.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .expect("rustls certificate vector")
                .into_iter()
                .map(Certificate::from_rustls_pki)
                .collect()
        })
    }

    /// Retrieves handshake data associated with the connection.
    pub fn handshake_data(&self) -> HandshakeData {
        let hd = self
            .quic_connection
            .handshake_data()
            .expect("fully established connection")
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .expect("valid downcast");

        HandshakeData {
            alpn: hd.protocol,
            server_name: hd.server_name,
        }
    }

    /// Returns a reference to the inner QUIC connection.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    #[inline(always)]
    pub fn quic_connection(&self) -> &quinn::Connection {
        &self.quic_connection
    }

    /// Returns a mutable reference to the inner QUIC connection.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    #[inline(always)]
    pub fn quic_connection_mut(&mut self) -> &mut quinn::Connection {
        &mut self.quic_connection
    }
}

#[cfg(all(test, feature = "self-signed"))]
mod tests {
    use super::*;
    use crate::driver::streams::session::StreamSession;
    use crate::driver::streams::ProtoReadError;
    use crate::endpoint::endpoint_side::Client;
    use crate::endpoint::endpoint_side::Server;
    use crate::error::ApplicationClose;
    use crate::tls::Sha256Digest;
    use crate::ClientConfig;
    use crate::Endpoint;
    use crate::Identity;
    use crate::ServerConfig;
    use std::time::Instant;
    use wtransport_proto::bytes::IoReadError;
    use wtransport_proto::capsule::Capsule;
    use wtransport_proto::frame::FrameKind;
    use wtransport_proto::session::SessionRequest as SessionRequestProto;

    fn server_endpoint() -> (Endpoint<Server>, String, Sha256Digest) {
        let identity = Identity::self_signed(["localhost"]).unwrap();
        let hash = identity.certificate_chain().as_slice()[0].hash();

        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address(SocketAddr::from(([127, 0, 0, 1], 0)))
                .with_identity(identity)
                .build(),
        )
        .unwrap();
        let url = format!("https://127.0.0.1:{}", server.local_addr().unwrap().port());

        (server, url, hash)
    }

    fn client_endpoint(hash: Sha256Digest) -> Endpoint<Client> {
        Endpoint::client(
            ClientConfig::builder()
                .with_bind_address(SocketAddr::from(([127, 0, 0, 1], 0)))
                .with_server_certificate_hashes([hash])
                .build(),
        )
        .unwrap()
    }

    async fn accept(server: &Endpoint<Server>) -> Connection {
        server.accept().await.await.unwrap().accept().await.unwrap()
    }

    async fn session_pair() -> (Connection, Connection) {
        let (server, url, hash) = server_endpoint();
        let client = client_endpoint(hash);

        tokio::join!(accept(&server), async {
            client.connect(url).await.unwrap()
        })
    }

    /// Opens a session whose CONNECT stream only the test reads. The client's QUIC stack
    /// acknowledges what the server sends, and nothing answers it.
    async fn silent_client(
        url: &str,
        hash: Sha256Digest,
    ) -> (quinn::Connection, Driver, StreamSession) {
        let config = ClientConfig::builder()
            .with_bind_address(SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_server_certificate_hashes([hash])
            .build();

        let mut endpoint = quinn::Endpoint::new(
            config.endpoint_config,
            None,
            config.bind_address_config.bind_socket().unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(config.quic_config);

        let address = url.strip_prefix("https://").unwrap().parse().unwrap();
        let quic_connection = endpoint
            .connect(address, "127.0.0.1")
            .unwrap()
            .await
            .unwrap();

        let driver = Driver::init(quic_connection.clone());
        driver.accept_settings().await.unwrap();

        let mut stream_session = driver
            .open_session(SessionRequestProto::new(url).unwrap())
            .await
            .unwrap();
        stream_session
            .write_frame(stream_session.request().headers().generate_frame())
            .await
            .unwrap();
        let response = stream_session.read_frame().await.unwrap();
        assert!(matches!(response.kind(), FrameKind::Headers));

        (quic_connection, driver, stream_session)
    }

    fn application_closed(error_code: u32, reason: &str) -> ConnectionError {
        ConnectionError::ApplicationClosed(ApplicationClose::new(
            VarInt::from_u32(error_code),
            reason.as_bytes().to_vec().into_boxed_slice(),
        ))
    }

    /// Asserts the QUIC connection close seen by `connection` does not carry `error_code`.
    fn assert_not_in_quic_close(connection: &Connection, error_code: u32) {
        assert!(!matches!(
            connection.quic_connection.close_reason(),
            Some(quinn::ConnectionError::ApplicationClosed(close))
                if close.error_code == quinn::VarInt::from_u32(error_code)
        ));
    }

    #[tokio::test]
    async fn close_session_sends_code_and_reason_in_capsule() {
        let (server, client) = session_pair().await;

        let (closed, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                client.closed(),
                server.close_session(4001, "access revoked")
            )
        })
        .await
        .unwrap();

        assert_eq!(closed, application_closed(4001, "access revoked"));
        assert_not_in_quic_close(&client, 4001);
        assert_eq!(server.closed().await, ConnectionError::LocallyClosed);
    }

    #[tokio::test]
    async fn close_session_from_client_reaches_server() {
        let (server, client) = session_pair().await;

        tokio::spawn(async move { client.close_session(7, "bye").await });

        let closed = tokio::time::timeout(Duration::from_secs(5), server.closed())
            .await
            .unwrap();
        assert_eq!(closed, application_closed(7, "bye"));
        assert_not_in_quic_close(&server, 7);
    }

    #[tokio::test]
    async fn close_session_right_after_accept_sends_capsule() {
        let (server, url, hash) = server_endpoint();
        let client = client_endpoint(hash);

        // The driver may still hold the accepted session in its queue. The worker then has
        // both requests ready and must take the session first.
        for _ in 0..16 {
            let closing = async {
                let connection = accept(&server).await;
                connection.close_session(4001, "access revoked").await;
            };

            let ((), closed) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(closing, async {
                    client.connect(url.as_str()).await.unwrap().closed().await
                })
            })
            .await
            .unwrap();

            assert_eq!(closed, application_closed(4001, "access revoked"));
        }
    }

    #[tokio::test]
    async fn crossing_close_sessions_return_before_timeout() {
        let (server, client) = session_pair().await;

        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                server.close_session(4001, "server"),
                client.close_session(4002, "client")
            )
        })
        .await
        .unwrap();

        assert_eq!(server.closed().await, ConnectionError::LocallyClosed);
        assert_eq!(client.closed().await, ConnectionError::LocallyClosed);
    }

    #[tokio::test]
    async fn close_session_sends_capsule_then_fin() {
        let (server, url, hash) = server_endpoint();

        let (connection, (_quic_connection, _driver, mut stream_session)) =
            tokio::join!(accept(&server), silent_client(&url, hash));
        tokio::spawn(async move { connection.close_session(4001, "access revoked").await });

        let frame = stream_session.read_frame().await.unwrap();
        let close =
            CloseWebTransportSession::with_capsule(&Capsule::with_frame(&frame).unwrap()).unwrap();
        assert_eq!(close.error_code(), VarInt::from_u32(4001));
        assert_eq!(close.reason(), "access revoked");

        assert!(matches!(
            stream_session.read_frame().await,
            Err(ProtoReadError::IO(IoReadError::ImmediateFin))
        ));
    }

    #[tokio::test]
    async fn close_session_closes_connection_when_peer_never_answers() {
        let (server, url, hash) = server_endpoint();

        let (connection, (client_quic_connection, _driver, _stream_session)) =
            tokio::join!(accept(&server), silent_client(&url, hash));

        let start = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(5),
            connection.close_session(4001, "access revoked"),
        )
        .await
        .unwrap();

        assert!(start.elapsed() >= Duration::from_secs(3));
        assert_eq!(connection.closed().await, ConnectionError::LocallyClosed);
        // H3_NO_ERROR.
        assert!(matches!(
            client_quic_connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(close)
                if close.error_code == quinn::VarInt::from_u32(0x100)
        ));
    }

    #[tokio::test]
    async fn close_session_returns_when_already_closed() {
        let (server, _client) = session_pair().await;

        tokio::time::timeout(Duration::from_secs(5), async {
            server.close_session(4001, "access revoked").await;
            server.close_session(4002, "again").await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn close_session_after_close_sends_nothing() {
        let (server, client) = session_pair().await;
        server.close(VarInt::from_u32(9), b"gone");

        tokio::time::timeout(
            Duration::from_secs(5),
            server.close_session(4001, "access revoked"),
        )
        .await
        .unwrap();

        assert_eq!(server.closed().await, ConnectionError::LocallyClosed);
        assert_eq!(client.closed().await, application_closed(9, "gone"));
    }

    #[tokio::test]
    async fn closed_agrees_with_accept_after_h3_error() {
        let (server, url, hash) = server_endpoint();

        let (connection, (_quic_connection, _driver, mut stream_session)) =
            tokio::join!(accept(&server), silent_client(&url, hash));
        // A reset CONNECT stream is an H3_CLOSED_CRITICAL_STREAM error.
        stream_session.reset(VarInt::from_u32(0));

        let closed = tokio::time::timeout(Duration::from_secs(5), connection.closed())
            .await
            .unwrap();
        assert!(matches!(closed, ConnectionError::LocalH3Error(_)));
        assert_eq!(connection.accept_bi().await.unwrap_err(), closed);
    }

    #[tokio::test]
    async fn close_session_goes_on_when_future_dropped() {
        let (server, client) = session_pair().await;

        // Polls the close once, then drops it.
        tokio::select! {
            biased;
            () = server.close_session(4001, "access revoked") => unreachable!(),
            () = std::future::ready(()) => {}
        }

        let closed = tokio::time::timeout(Duration::from_secs(5), client.closed())
            .await
            .unwrap();
        assert_eq!(closed, application_closed(4001, "access revoked"));
    }
}
