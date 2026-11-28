//! End-to-end TCP integration tests for `premier-ssh` exercising
//! `serve_ssh_with_limits` over loopback TCP with a real `russh::client`.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use premier_ssh::{
    GitService, SshAuthenticatedUser, SshGitBackend, SshLimits, async_trait,
    load_or_generate_host_key, serve_ssh_with_limits,
};
use russh::client::{self, Handle, Msg};
use russh::keys::key::{PrivateKeyWithHashAlg, safe_rng};
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, Disconnect};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

const WIRE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

const OID_MAIN: &str = "1111111111111111111111111111111111111111";
const OID_OTHER: &str = "2222222222222222222222222222222222222222";
const ZERO_OID: &str = "0000000000000000000000000000000000000000";

fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() + 4;
    let mut out = format!("{len:04x}").into_bytes();
    out.extend_from_slice(payload);
    out
}

fn generate_ed25519_key() -> Result<PrivateKey> {
    PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
        .map_err(|e| anyhow!("failed to generate Ed25519 key: {e}"))
}

fn key_with_hash_alg(key: &PrivateKey) -> Result<PrivateKeyWithHashAlg> {
    Ok(PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdvertiseCall {
    username: String,
    repo: String,
    service: GitService,
    protocol_v2: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UploadCall {
    username: String,
    repo: String,
    protocol_v2: bool,
    stdin: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiveCall {
    username: String,
    repo: String,
    stdin: Vec<u8>,
}

struct MockSshBackend {
    authorized_keys: HashMap<String, String>,
    advertise_calls: Mutex<Vec<AdvertiseCall>>,
    upload_calls: Mutex<Vec<UploadCall>>,
    receive_calls: Mutex<Vec<ReceiveCall>>,
}

impl MockSshBackend {
    fn with_user_key(username: &str, pubkey_openssh: String) -> Self {
        let mut authorized_keys = HashMap::new();
        authorized_keys.insert(username.to_owned(), pubkey_openssh);
        Self {
            authorized_keys,
            advertise_calls: Mutex::new(Vec::new()),
            upload_calls: Mutex::new(Vec::new()),
            receive_calls: Mutex::new(Vec::new()),
        }
    }

    fn advertise_calls(&self) -> Result<Vec<AdvertiseCall>> {
        self.advertise_calls
            .lock()
            .map(|g| g.clone())
            .map_err(|_| anyhow!("advertise_calls mutex poisoned"))
    }

    fn upload_calls(&self) -> Result<Vec<UploadCall>> {
        self.upload_calls
            .lock()
            .map(|g| g.clone())
            .map_err(|_| anyhow!("upload_calls mutex poisoned"))
    }

    fn receive_calls(&self) -> Result<Vec<ReceiveCall>> {
        self.receive_calls
            .lock()
            .map(|g| g.clone())
            .map_err(|_| anyhow!("receive_calls mutex poisoned"))
    }
}

#[async_trait]
impl SshGitBackend for MockSshBackend {
    async fn authenticate_pubkey(
        &self,
        username: &str,
        key_openssh: &str,
    ) -> Option<SshAuthenticatedUser> {
        let expected = self.authorized_keys.get(username)?;
        if expected == key_openssh {
            Some(SshAuthenticatedUser {
                username: username.to_owned(),
                is_owner: true,
            })
        } else {
            None
        }
    }

    async fn advertise_refs(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        service: GitService,
        protocol_v2: bool,
    ) -> std::result::Result<Vec<u8>, String> {
        if let Ok(mut calls) = self.advertise_calls.lock() {
            calls.push(AdvertiseCall {
                username: user.username.clone(),
                repo: repo.to_owned(),
                service,
                protocol_v2,
            });
        }

        if repo == "denied-fatal" {
            return Err("fatal: repository access denied".to_owned());
        }

        // Deliberately include Smart HTTP `# service=...\n0000` preambles so tests verify
        // that `premier-ssh` strips them automatically before writing to SSH stdout.
        match (service, protocol_v2) {
            (GitService::UploadPack, true) => {
                let mut out = pkt_line(b"# service=git-upload-pack\n");
                out.extend_from_slice(b"0000");
                out.extend_from_slice(&pkt_line(b"version 2\n"));
                out.extend_from_slice(&pkt_line(b"agent=premier/0.1\n"));
                out.extend_from_slice(&pkt_line(b"ls-refs\n"));
                out.extend_from_slice(&pkt_line(b"fetch=shallow\n"));
                out.extend_from_slice(b"0000");
                Ok(out)
            }
            (GitService::UploadPack, false) => {
                let mut out = pkt_line(b"# service=git-upload-pack\n");
                out.extend_from_slice(b"0000");
                out.extend_from_slice(&pkt_line(
                    format!("{OID_MAIN} refs/heads/main\0multi_ack_detailed side-band-64k\n")
                        .as_bytes(),
                ));
                out.extend_from_slice(b"0000");
                Ok(out)
            }
            (GitService::ReceivePack, _) => {
                let mut out = pkt_line(b"# service=git-receive-pack\n");
                out.extend_from_slice(b"0000");
                out.extend_from_slice(&pkt_line(
                    format!("{OID_MAIN} refs/heads/feat\0report-status delete-refs\n").as_bytes(),
                ));
                out.extend_from_slice(b"0000");
                Ok(out)
            }
        }
    }

    async fn handle_upload_pack(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        protocol_v2: bool,
        stdin: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        if let Ok(mut calls) = self.upload_calls.lock() {
            calls.push(UploadCall {
                username: user.username.clone(),
                repo: repo.to_owned(),
                protocol_v2,
                stdin: stdin.to_vec(),
            });
        }

        if protocol_v2 {
            let mut out = pkt_line(format!("{OID_MAIN} refs/heads/main\n").as_bytes());
            out.extend_from_slice(b"0000");
            return Ok(out);
        }

        // Protocol v0/v1: return empty response for intermediate `have ... 0000` batches so
        // `premier-ssh` writes `0008NAK\n` and keeps the channel open, and return a packfile
        // response once `0009done\n` arrives.
        if stdin.ends_with(b"0009done\n") {
            let mut out = b"0008NAK\n".to_vec();
            out.extend_from_slice(b"PACK\x00\x00\x00\x02\x00\x00\x00\x00");
            out.extend_from_slice(&[0xEE; 20]);
            Ok(out)
        } else {
            Ok(Vec::new())
        }
    }

    async fn handle_receive_pack(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        stdin: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, String> {
        if let Ok(mut calls) = self.receive_calls.lock() {
            calls.push(ReceiveCall {
                username: user.username.clone(),
                repo: repo.to_owned(),
                stdin,
            });
        }

        let mut out = pkt_line(b"unpack ok\n");
        out.extend_from_slice(&pkt_line(b"ok refs/heads/feat\n"));
        out.extend_from_slice(b"0000");
        Ok(out)
    }
}

struct TestClientHandler {
    expected_host_key: PublicKey,
}

impl client::Handler for TestClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(matches!(
            server_public_key,
            PublicKeyOrCertificate::PublicKey { key, .. } if key == &self.expected_host_key
        ))
    }
}

struct TestSshServer {
    addr: SocketAddr,
    host_public_key: PublicKey,
    backend: Arc<MockSshBackend>,
    task: JoinHandle<Result<()>>,
    _temp_dir: TempDir,
}

impl TestSshServer {
    fn start(
        authorized_user: &str,
        authorized_key: &PrivateKey,
        limits: SshLimits,
    ) -> Result<Self> {
        let temp_dir = tempfile::tempdir().context("create temp dir for host key")?;
        let host_key_path = temp_dir
            .path()
            .join(".premier")
            .join("ssh_host_ed25519.key");
        let host_key = load_or_generate_host_key(&host_key_path)?;
        let host_public_key = host_key.public_key().clone();

        let pubkey_openssh = authorized_key
            .public_key()
            .to_openssh()
            .map_err(|e| anyhow!("failed to encode authorized public key: {e}"))?;
        let backend = Arc::new(MockSshBackend::with_user_key(
            authorized_user,
            pubkey_openssh,
        ));

        let listener =
            TcpListener::bind("127.0.0.1:0").context("allocate ephemeral loopback port")?;
        let addr = listener.local_addr().context("read ephemeral local_addr")?;
        drop(listener);

        let backend_for_task: Arc<dyn SshGitBackend> =
            Arc::clone(&backend) as Arc<dyn SshGitBackend>;
        let task = tokio::spawn(async move {
            serve_ssh_with_limits(addr, host_key_path, backend_for_task, limits).await
        });

        Ok(Self {
            addr,
            host_public_key,
            backend,
            task,
            _temp_dir: temp_dir,
        })
    }

    async fn connect(&self) -> Result<Handle<TestClientHandler>> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let config = Arc::new(client::Config::default());

        loop {
            if self.task.is_finished() {
                bail!("SSH server task exited prematurely before accepting client");
            }
            let handler = TestClientHandler {
                expected_host_key: self.host_public_key.clone(),
            };
            match client::connect(Arc::clone(&config), self.addr, handler).await {
                Ok(handle) => return Ok(handle),
                Err(russh::Error::IO(err))
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::AddrNotAvailable
                    ) && Instant::now() < deadline =>
                {
                    sleep(Duration::from_millis(15)).await;
                }
                Err(err) => {
                    return Err(anyhow!(
                        "failed to connect SSH client to {}: {err}",
                        self.addr
                    ));
                }
            }
        }
    }

    async fn connect_authenticated(
        &self,
        username: &str,
        key: &PrivateKey,
    ) -> Result<Handle<TestClientHandler>> {
        let mut session = self.connect().await?;
        let auth = session
            .authenticate_publickey(username, key_with_hash_alg(key)?)
            .await
            .context("authenticate_publickey failed")?;
        if !auth.success() {
            bail!("expected publickey auth to succeed for {username}");
        }
        Ok(session)
    }
}

impl Drop for TestSshServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Default)]
struct ChannelOutcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    saw_eof: bool,
    saw_success: bool,
    saw_failure: bool,
}

async fn wait_for_request_reply(channel: &mut Channel<Msg>) -> Result<bool> {
    timeout(WIRE_TIMEOUT, async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Success => return Ok(true),
                ChannelMsg::Failure => return Ok(false),
                ChannelMsg::WindowAdjusted { .. } => {}
                other => {
                    bail!("unexpected channel message while awaiting request reply: {other:?}")
                }
            }
        }
        bail!("channel closed before request reply arrived")
    })
    .await
    .context("timed out waiting for channel request reply")?
}

async fn read_stdout_until(
    channel: &mut Channel<Msg>,
    predicate: impl Fn(&[u8]) -> bool,
) -> Result<Vec<u8>> {
    timeout(WIRE_TIMEOUT, async {
        let mut stdout = Vec::new();
        while !predicate(&stdout) {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::ExtendedData { ext, data }) => {
                    bail!(
                        "unexpected extended data (ext={ext}) while reading stdout: {:?}",
                        String::from_utf8_lossy(&data)
                    );
                }
                Some(other) => {
                    bail!(
                        "unexpected channel message while reading stdout (got {} bytes so far): {other:?}",
                        stdout.len()
                    );
                }
                None => {
                    bail!(
                        "channel closed prematurely while reading stdout (got {} bytes: {:?})",
                        stdout.len(),
                        String::from_utf8_lossy(&stdout)
                    );
                }
            }
        }
        Ok(stdout)
    })
    .await
    .context("timed out waiting for expected stdout bytes")?
}

async fn drain_channel(channel: &mut Channel<Msg>) -> Result<ChannelOutcome> {
    timeout(WIRE_TIMEOUT, async {
        let mut out = ChannelOutcome::default();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { ext, data } => {
                    if ext != SSH_EXTENDED_DATA_STDERR {
                        bail!("unexpected extended data type {ext}");
                    }
                    out.stderr.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    out.exit_status = Some(exit_status);
                }
                ChannelMsg::Eof => out.saw_eof = true,
                ChannelMsg::Success => out.saw_success = true,
                ChannelMsg::Failure => out.saw_failure = true,
                ChannelMsg::Close => break,
                ChannelMsg::WindowAdjusted { .. } => {}
                other => bail!("unexpected channel message while draining: {other:?}"),
            }
        }
        Ok(out)
    })
    .await
    .context("timed out draining SSH channel to close")?
}

#[tokio::test]
async fn pubkey_only_authentication_enforcement() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let registered_key = generate_ed25519_key()?;
        let unregistered_key = generate_ed25519_key()?;
        let server = TestSshServer::start("alice", &registered_key, SshLimits::default())?;

        // 1. `authenticate_none` is rejected.
        {
            let mut session = server.connect().await?;
            let accepted = session
                .authenticate_none("alice")
                .await
                .context("authenticate_none call")?;
            assert!(!accepted.success(), "none authentication must be rejected");
            // On the same connection, the registered Ed25519 key still authenticates cleanly.
            let pk_ok = session
                .authenticate_publickey("alice", key_with_hash_alg(&registered_key)?)
                .await
                .context("authenticate_publickey after none")?;
            assert!(
                pk_ok.success(),
                "registered Ed25519 key should succeed after rejected none"
            );
            let _ = session
                .disconnect(Disconnect::ByApplication, "done", "en")
                .await;
        }

        // 2. `authenticate_password` is rejected.
        {
            let mut session = server.connect().await?;
            let accepted = session
                .authenticate_password("alice", "correct-horse-battery-staple")
                .await
                .context("authenticate_password call")?;
            assert!(
                !accepted.success(),
                "password authentication must be rejected"
            );
            let _ = session
                .disconnect(Disconnect::ByApplication, "done", "en")
                .await;
        }

        // 3. Unregistered Ed25519 key is rejected.
        {
            let mut session = server.connect().await?;
            let accepted = session
                .authenticate_publickey("alice", key_with_hash_alg(&unregistered_key)?)
                .await
                .context("authenticate_publickey with unregistered key")?;
            assert!(
                !accepted.success(),
                "unregistered Ed25519 key must be rejected"
            );
            let _ = session
                .disconnect(Disconnect::ByApplication, "done", "en")
                .await;
        }

        // 4. Registered key presented for a different username is rejected.
        {
            let mut session = server.connect().await?;
            let accepted = session
                .authenticate_publickey("mallory", key_with_hash_alg(&registered_key)?)
                .await
                .context("authenticate_publickey with wrong user")?;
            assert!(!accepted.success(), "mismatched username must be rejected");
            let _ = session
                .disconnect(Disconnect::ByApplication, "done", "en")
                .await;
        }

        // 5. Registered Ed25519 key authenticates cleanly and can open a session channel.
        {
            let session = server
                .connect_authenticated("alice", &registered_key)
                .await?;
            let channel = session
                .channel_open_session()
                .await
                .context("channel_open_session after pubkey auth")?;
            channel.close().await.context("close session channel")?;
            let _ = session
                .disconnect(Disconnect::ByApplication, "done", "en")
                .await;
        }

        Ok(())
    })
    .await
    .context("pubkey_only_authentication_enforcement timed out")?
}

#[tokio::test]
async fn command_allowlist_and_rfc4254_refusal() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let key = generate_ed25519_key()?;
        let server = TestSshServer::start("alice", &key, SshLimits::default())?;
        let session = server.connect_authenticated("alice", &key).await?;

        // 1. Interactive `request_shell` is refused per RFC 4254 without emitting data before Failure.
        {
            let mut ch = session.channel_open_session().await?;
            ch.request_shell(true).await?;
            let ok = wait_for_request_reply(&mut ch).await?;
            assert!(!ok, "request_shell must receive ChannelMsg::Failure");
            let outcome = drain_channel(&mut ch).await?;
            assert!(
                outcome.stdout.is_empty(),
                "refused shell must not write stdout"
            );
            assert!(
                outcome.stderr.is_empty(),
                "refused shell must not write stderr"
            );
            assert!(
                outcome.saw_eof,
                "refused shell channel should send EOF and close"
            );
        }

        // 2. `request_pty` is refused with ChannelMsg::Failure.
        {
            let mut ch = session.channel_open_session().await?;
            ch.request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
                .await?;
            let ok = wait_for_request_reply(&mut ch).await?;
            assert!(!ok, "request_pty must receive ChannelMsg::Failure");
            ch.close().await?;
        }

        // 3. `request_subsystem("sftp")` is refused with ChannelMsg::Failure.
        {
            let mut ch = session.channel_open_session().await?;
            ch.request_subsystem(true, "sftp").await?;
            let ok = wait_for_request_reply(&mut ch).await?;
            assert!(
                !ok,
                "request_subsystem(sftp) must receive ChannelMsg::Failure"
            );
            ch.close().await?;
        }

        // 4. Disallowed `exec` commands fail with exit 1 and single-prefixed `fatal:` stderr.
        let disallowed_commands = [
            "id",
            "git-upload-pack 'repo'; id",
            "git-upload-pack '../escape'",
        ];
        for cmd in disallowed_commands {
            let mut ch = session.channel_open_session().await?;
            ch.exec(true, cmd).await?;
            let ok = wait_for_request_reply(&mut ch).await?;
            assert!(
                ok,
                "disallowed exec `{cmd}` should accept RFC 4254 exec so Git receives fatal stderr"
            );
            let outcome = drain_channel(&mut ch).await?;
            let stderr = String::from_utf8_lossy(&outcome.stderr);
            assert_eq!(
                outcome.exit_status,
                Some(1),
                "expected exit status 1 for `{cmd}`, stderr={stderr:?}"
            );
            assert!(outcome.saw_eof, "expected EOF on failed exec `{cmd}`");
            assert!(
                outcome.stdout.is_empty(),
                "expected empty stdout for `{cmd}`"
            );
            assert!(
                stderr.starts_with("fatal: "),
                "expected stderr to start with `fatal: ` for `{cmd}`, got {stderr:?}"
            );
            assert!(
                !stderr.contains("fatal: fatal:"),
                "stderr must never double-prefix `fatal: fatal:` for `{cmd}`, got {stderr:?}"
            );
        }

        // 5. Backend error already starting with `fatal: ` is never double-prefixed on the wire.
        {
            let mut ch = session.channel_open_session().await?;
            ch.exec(true, "git-upload-pack '/denied-fatal.git'").await?;
            let ok = wait_for_request_reply(&mut ch).await?;
            assert!(ok, "allowed exec command should return ChannelMsg::Success");
            let outcome = drain_channel(&mut ch).await?;
            let stderr = String::from_utf8_lossy(&outcome.stderr);
            assert_eq!(outcome.exit_status, Some(1));
            assert_eq!(stderr, "fatal: repository access denied\n");
            assert!(!stderr.contains("fatal: fatal:"));
        }

        let _ = session
            .disconnect(Disconnect::ByApplication, "done", "en")
            .await;
        Ok(())
    })
    .await
    .context("command_allowlist_and_rfc4254_refusal timed out")?
}

#[tokio::test]
async fn protocol_v2_upload_pack_full_wire_exchange() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let key = generate_ed25519_key()?;
        let server = TestSshServer::start("alice", &key, SshLimits::default())?;
        let session = server.connect_authenticated("alice", &key).await?;

        let mut ch = session.channel_open_session().await?;
        ch.set_env(true, "GIT_PROTOCOL", "version=2").await?;
        assert!(
            wait_for_request_reply(&mut ch).await?,
            "GIT_PROTOCOL=version=2 env request must succeed"
        );

        ch.exec(true, "git-upload-pack '/repo.git'").await?;
        assert!(
            wait_for_request_reply(&mut ch).await?,
            "git-upload-pack exec must succeed"
        );

        // Read capability advertisement and verify Smart HTTP `# service=` preamble was stripped.
        let adv = read_stdout_until(&mut ch, |buf| buf.ends_with(b"0000")).await?;
        let adv_str = String::from_utf8_lossy(&adv);
        assert!(
            adv.starts_with(b"000eversion 2\n"),
            "expected protocol v2 advertisement starting with `000eversion 2\\n`, got {adv_str:?}"
        );
        assert!(
            !adv_str.contains("# service="),
            "SSH advertisement must not contain Smart HTTP `# service=` preamble: {adv_str:?}"
        );
        assert!(adv_str.contains("ls-refs\n"), "expected ls-refs capability");

        // Send a `command=ls-refs` frame terminated by `0000` (without sending client EOF).
        let ls_refs_req = b"0014command=ls-refs\n0001000csymrefs\n0000";
        ch.data(&ls_refs_req[..]).await?;

        let ls_refs_resp = read_stdout_until(&mut ch, |buf| buf.ends_with(b"0000")).await?;
        let resp_str = String::from_utf8_lossy(&ls_refs_resp);
        assert!(
            resp_str.contains(OID_MAIN) && resp_str.contains("refs/heads/main"),
            "expected ls-refs response containing main ref, got {resp_str:?}"
        );

        // Send standalone `0000` terminate flush (without client EOF) -> server exits 0 and closes.
        ch.data(&b"0000"[..]).await?;
        let outcome = drain_channel(&mut ch).await?;
        assert_eq!(outcome.exit_status, Some(0));
        assert!(
            outcome.saw_eof,
            "expected server EOF after v2 terminate flush"
        );
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.is_empty());

        let adv_calls = server.backend.advertise_calls()?;
        assert_eq!(
            adv_calls,
            vec![AdvertiseCall {
                username: "alice".to_owned(),
                repo: "repo".to_owned(),
                service: GitService::UploadPack,
                protocol_v2: true,
            }]
        );
        let upload_calls = server.backend.upload_calls()?;
        assert_eq!(
            upload_calls,
            vec![UploadCall {
                username: "alice".to_owned(),
                repo: "repo".to_owned(),
                protocol_v2: true,
                stdin: ls_refs_req.to_vec(),
            }]
        );

        let _ = session
            .disconnect(Disconnect::ByApplication, "done", "en")
            .await;
        Ok(())
    })
    .await
    .context("protocol_v2_upload_pack_full_wire_exchange timed out")?
}

#[tokio::test]
async fn protocol_v0_upload_pack_multi_round_negotiation_and_done() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let key = generate_ed25519_key()?;
        let server = TestSshServer::start("alice", &key, SshLimits::default())?;
        let session = server.connect_authenticated("alice", &key).await?;

        // Exec `git-upload-pack '/repo.git'` WITHOUT setting `GIT_PROTOCOL=version=2`.
        let mut ch = session.channel_open_session().await?;
        ch.exec(true, "git-upload-pack '/repo.git'").await?;
        assert!(wait_for_request_reply(&mut ch).await?);

        // Read v0 ref advertisement.
        let adv = read_stdout_until(&mut ch, |buf| buf.ends_with(b"0000")).await?;
        let adv_str = String::from_utf8_lossy(&adv);
        assert!(
            !adv_str.contains("# service="),
            "SSH v0 advertisement must not contain `# service=`: {adv_str:?}"
        );
        assert!(
            adv_str.contains(OID_MAIN) && adv_str.contains("refs/heads/main"),
            "expected v0 ref advertisement with main ref, got {adv_str:?}"
        );

        // Round 1: send `want <oid>\n0000` + `have <other>\n0000` WITHOUT client EOF.
        let want_pkt = pkt_line(format!("want {OID_MAIN} side-band-64k\n").as_bytes());
        let have_pkt = pkt_line(format!("have {OID_OTHER}\n").as_bytes());
        let mut round1 = Vec::new();
        round1.extend_from_slice(&want_pkt);
        round1.extend_from_slice(b"0000");
        round1.extend_from_slice(&have_pkt);
        round1.extend_from_slice(b"0000");
        ch.data(&round1[..]).await?;

        // Server must reply with `0008NAK\n` and keep the channel open (anti-deadlock).
        let nak = read_stdout_until(&mut ch, |buf| buf.len() >= 8).await?;
        assert_eq!(nak, b"0008NAK\n");

        // Round 2: send `0009done\n` WITHOUT calling `ch.eof()`.
        // Server must dispatch `handle_upload_pack(..., false, ...)` immediately, stream the
        // response, exit 0, and close.
        ch.data(&b"0009done\n"[..]).await?;
        let outcome = drain_channel(&mut ch).await?;
        assert_eq!(outcome.exit_status, Some(0));
        assert!(outcome.saw_eof);
        assert!(outcome.stderr.is_empty());
        assert!(
            outcome.stdout.starts_with(b"0008NAK\nPACK"),
            "expected NAK + PACK payload after done, got {:?}",
            String::from_utf8_lossy(&outcome.stdout)
        );

        let adv_calls = server.backend.advertise_calls()?;
        assert_eq!(
            adv_calls,
            vec![AdvertiseCall {
                username: "alice".to_owned(),
                repo: "repo".to_owned(),
                service: GitService::UploadPack,
                protocol_v2: false,
            }]
        );

        let upload_calls = server.backend.upload_calls()?;
        let expected_have_batch = [have_pkt.as_slice(), b"0000"].concat();
        let expected_full_done = [
            want_pkt.as_slice(),
            b"0000",
            have_pkt.as_slice(),
            b"0009done\n",
        ]
        .concat();
        assert_eq!(
            upload_calls,
            vec![
                UploadCall {
                    username: "alice".to_owned(),
                    repo: "repo".to_owned(),
                    protocol_v2: false,
                    stdin: expected_have_batch,
                },
                UploadCall {
                    username: "alice".to_owned(),
                    repo: "repo".to_owned(),
                    protocol_v2: false,
                    stdin: expected_full_done,
                },
            ]
        );

        let _ = session
            .disconnect(Disconnect::ByApplication, "done", "en")
            .await;
        Ok(())
    })
    .await
    .context("protocol_v0_upload_pack_multi_round_negotiation_and_done timed out")?
}

#[tokio::test]
async fn packless_receive_pack_delete_and_standalone_flush() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let key = generate_ed25519_key()?;
        let server = TestSshServer::start("alice", &key, SshLimits::default())?;
        let session = server.connect_authenticated("alice", &key).await?;

        // Test 1: Standalone `0000` flush -> server exits 0 immediately without client EOF.
        {
            let mut ch = session.channel_open_session().await?;
            ch.exec(true, "git-receive-pack '/repo.git'").await?;
            assert!(wait_for_request_reply(&mut ch).await?);

            let adv = read_stdout_until(&mut ch, |buf| buf.ends_with(b"0000")).await?;
            let adv_str = String::from_utf8_lossy(&adv);
            assert!(!adv_str.contains("# service="));
            assert!(adv_str.contains("refs/heads/feat"));

            // Send standalone `0000` with NO `ch.eof()`.
            ch.data(&b"0000"[..]).await?;
            let outcome = drain_channel(&mut ch).await?;
            assert_eq!(outcome.exit_status, Some(0));
            assert!(outcome.saw_eof);
            assert!(outcome.stdout.is_empty());
            assert!(outcome.stderr.is_empty());
            assert!(
                server.backend.receive_calls()?.is_empty(),
                "standalone 0000 flush must not invoke handle_receive_pack"
            );
        }

        // Test 2: Packless delete command -> server dispatches `handle_receive_pack` immediately,
        // writes `report-status`, exits 0, and closes without client EOF.
        {
            let mut ch = session.channel_open_session().await?;
            ch.exec(true, "git-receive-pack '/repo.git'").await?;
            assert!(wait_for_request_reply(&mut ch).await?);

            let _adv = read_stdout_until(&mut ch, |buf| buf.ends_with(b"0000")).await?;

            let mut delete_payload = pkt_line(
                format!("{OID_MAIN} {ZERO_OID} refs/heads/feat\0report-status\n").as_bytes(),
            );
            delete_payload.extend_from_slice(b"0000");
            // Send delete command with NO packfile and NO `ch.eof()`.
            ch.data(&delete_payload[..]).await?;

            let outcome = drain_channel(&mut ch).await?;
            let stdout_str = String::from_utf8_lossy(&outcome.stdout);
            assert_eq!(outcome.exit_status, Some(0));
            assert!(outcome.saw_eof);
            assert!(outcome.stderr.is_empty());
            assert!(
                stdout_str.contains("unpack ok\n") && stdout_str.contains("ok refs/heads/feat\n"),
                "expected report-status on stdout, got {stdout_str:?}"
            );
            assert!(outcome.stdout.ends_with(b"0000"));

            let receive_calls = server.backend.receive_calls()?;
            assert_eq!(
                receive_calls,
                vec![ReceiveCall {
                    username: "alice".to_owned(),
                    repo: "repo".to_owned(),
                    stdin: delete_payload,
                }]
            );
        }

        let _ = session
            .disconnect(Disconnect::ByApplication, "done", "en")
            .await;
        Ok(())
    })
    .await
    .context("packless_receive_pack_delete_and_standalone_flush timed out")?
}

#[tokio::test]
async fn per_channel_request_byte_limit_enforcement() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let key = generate_ed25519_key()?;
        let tiny_limits = SshLimits {
            max_upload_pack_bytes: 512,
            max_receive_pack_bytes: 512,
        };
        let server = TestSshServer::start("alice", &key, tiny_limits)?;
        let session = server.connect_authenticated("alice", &key).await?;

        // Exceed `max_receive_pack_bytes` (512) on `git-receive-pack`.
        {
            let mut ch = session.channel_open_session().await?;
            ch.exec(true, "git-receive-pack '/repo.git'").await?;
            assert!(wait_for_request_reply(&mut ch).await?);

            let _adv = read_stdout_until(&mut ch, |buf| buf.ends_with(b"0000")).await?;

            // Send a valid non-deletion ref update + `0000` + non-empty PACK header (fits in 512B),
            // then stream >512 total bytes without EOF.
            let mut chunk1 = pkt_line(
                format!("{OID_MAIN} {OID_OTHER} refs/heads/feat\0report-status\n").as_bytes(),
            );
            chunk1.extend_from_slice(b"0000");
            chunk1.extend_from_slice(b"PACK\x00\x00\x00\x02\x00\x00\x00\x01");
            assert!(chunk1.len() < 512);
            ch.data(&chunk1[..]).await?;

            let chunk2 = vec![0xAAu8; 600];
            ch.data(&chunk2[..]).await?;

            let outcome = drain_channel(&mut ch).await?;
            let stderr = String::from_utf8_lossy(&outcome.stderr);
            assert_eq!(
                outcome.exit_status,
                Some(1),
                "oversized receive-pack must fail with exit 1, stderr={stderr:?}"
            );
            assert!(outcome.saw_eof);
            assert!(
                stderr.starts_with("fatal: "),
                "expected `fatal: ` stderr, got {stderr:?}"
            );
            assert!(
                !stderr.contains("fatal: fatal:"),
                "stderr must not double-prefix `fatal: fatal:`, got {stderr:?}"
            );
            assert!(
                stderr.contains("512") && stderr.contains("git-receive-pack"),
                "expected byte limit diagnostic in stderr, got {stderr:?}"
            );
            assert!(
                server.backend.receive_calls()?.is_empty(),
                "oversized payload must be rejected before dispatching to backend"
            );
        }

        // Verify the server did not panic and the SSH connection still cleanly serves a new channel.
        {
            let mut ch = session.channel_open_session().await?;
            ch.exec(true, "git-receive-pack '/repo.git'").await?;
            assert!(wait_for_request_reply(&mut ch).await?);
            let _adv = read_stdout_until(&mut ch, |buf| buf.ends_with(b"0000")).await?;
            ch.data(&b"0000"[..]).await?;
            let outcome = drain_channel(&mut ch).await?;
            assert_eq!(outcome.exit_status, Some(0));
        }

        let _ = session
            .disconnect(Disconnect::ByApplication, "done", "en")
            .await;
        Ok(())
    })
    .await
    .context("per_channel_request_byte_limit_enforcement timed out")?
}
