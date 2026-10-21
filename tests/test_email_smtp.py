"""End-to-end email tests against a real SMTP conversation.

The other email tests stub the mailer, which proves the service's own
bookkeeping but not that a message ever leaves the process. These tests
speak the SMTP protocol to an in-process server, so aiosmtplib really
connects, really negotiates, and really hands over a MIME message.

No external provider (SendGrid, SES) and no network access is involved: the
server is a thread running its own event loop on localhost.
"""

import asyncio
import email
import threading
from email.message import Message

import pytest

from surrealengine_auth import SurrealEngineAuth
from surrealengine_auth.email_service import EmailService


# --------------------------------------------------------------------------- #
# A minimal SMTP server
# --------------------------------------------------------------------------- #


class FakeSMTPServer:
    """A single-threaded SMTP server that records what it is handed."""

    def __init__(
        self,
        *,
        require_auth=False,
        reject_recipients=False,
        expected_username="user",
        expected_password="pass",
    ):
        self.messages = []
        self.require_auth = require_auth
        self.reject_recipients = reject_recipients
        self.expected_username = expected_username
        self.expected_password = expected_password
        self.authenticated = False
        self._server = None
        self._loop = None
        self._thread = None
        self.port = None

    # -- lifecycle -- #

    def start(self):
        ready = threading.Event()

        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            loop.run_until_complete(self._serve(ready))
            loop.run_forever()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(timeout=10), "the SMTP server did not start"
        return self

    def stop(self):
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._shutdown)
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _shutdown(self):
        if self._server is not None:
            self._server.close()
        self._loop.stop()

    async def _serve(self, ready):
        self._server = await asyncio.start_server(
            self._handle, host="127.0.0.1", port=0
        )
        self.port = self._server.sockets[0].getsockname()[1]
        ready.set()

    # -- protocol -- #

    async def _handle(self, reader, writer):
        try:
            await self._conversation(reader, writer)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _conversation(self, reader, writer):
        await self._send(writer, "220 localhost ESMTP FakeSMTPServer")

        while True:
            line = await reader.readline()
            if not line:
                return
            command = line.decode("utf-8", "replace").strip()

            upper = command.upper()
            if upper.startswith("EHLO"):
                await self._send(
                    writer,
                    "250-localhost greets you\n"
                    "250-SIZE 10485760\n"
                    + ("250-AUTH PLAIN LOGIN\n" if self.require_auth else "")
                    + "250 HELP",
                )
            elif upper.startswith("HELO"):
                await self._send(writer, "250 localhost")
            elif upper.startswith("AUTH"):
                await self._authenticate(writer, command)
            elif upper.startswith("MAIL FROM"):
                await self._send(writer, "250 OK")
            elif upper.startswith("RCPT TO"):
                if self.reject_recipients:
                    await self._send(writer, "550 No such user here")
                else:
                    await self._send(writer, "250 OK")
            elif upper == "DATA":
                await self._send(
                    writer, "354 End data with <CR><LF>.<CR><LF>"
                )
                await self._read_message(reader, writer)
            elif upper == "RSET":
                await self._send(writer, "250 OK")
            elif upper == "NOOP":
                await self._send(writer, "250 OK")
            elif upper == "QUIT":
                await self._send(writer, "221 Bye")
                return
            else:
                await self._send(writer, "502 Command not implemented")

    async def _authenticate(self, writer, command):
        if not self.require_auth:
            await self._send(writer, "530 Authentication not enabled")
            return
        parts = command.split(" ", 2)
        if len(parts) == 3 and parts[1].upper() == "PLAIN":
            # AUTH PLAIN sends \0username\0password.
            import base64

            try:
                decoded = base64.b64decode(parts[2]).decode("utf-8")
            except Exception:
                decoded = ""
            parts_plain = decoded.split("\0")
            username = parts_plain[1] if len(parts_plain) > 1 else ""
            password = parts_plain[2] if len(parts_plain) > 2 else ""
            if username == self.expected_username and password == self.expected_password:
                self.authenticated = True
                await self._send(writer, "235 Authentication successful")
                return
        await self._send(writer, "535 Authentication failed")

    async def _read_message(self, reader, writer):
        chunks = []
        while True:
            line = await reader.readline()
            if not line or line in (b".\r\n", b".\n"):
                break
            # Undo dot-stuffing.
            if line.startswith(b".."):
                line = line[1:]
            chunks.append(line)
        self.messages.append(b"".join(chunks).decode("utf-8", "replace"))
        await self._send(writer, "250 OK: message queued")

    async def _send(self, writer, text):
        """Write one SMTP response.

        Every line ends with CRLF. A client that reads a *line* waits for the
        terminator, so a response without it hangs the client rather than
        being delivered late.
        """
        payload = text.replace("\n", "\r\n")
        if not payload.endswith("\r\n"):
            payload += "\r\n"
        writer.write(payload.encode("utf-8"))
        await writer.drain()

    # -- helpers -- #

    def last_message(self) -> Message:
        assert self.messages, "no message was delivered"
        return email.message_from_string(self.messages[-1])

    def bodies(self, message: Message):
        """The plain-text and HTML parts of a multipart message."""
        text = html = None
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() == "text/plain":
                text = part.get_payload(decode=True).decode("utf-8")
            elif part.get_content_type() == "text/html":
                html = part.get_payload(decode=True).decode("utf-8")
        return text, html


@pytest.fixture
def smtp():
    """A running SMTP server; stopped at the end of the test."""
    server = FakeSMTPServer().start()
    yield server
    server.stop()


@pytest.fixture
def smtp_rejecting():
    """A server that refuses every recipient."""
    server = FakeSMTPServer(reject_recipients=True).start()
    yield server
    server.stop()


@pytest.fixture
def smtp_auth():
    """A server that requires authentication."""
    server = FakeSMTPServer(require_auth=True).start()
    yield server
    server.stop()


def service_for(server: FakeSMTPServer, **kwargs) -> EmailService:
    return EmailService(
        smtp_host="127.0.0.1",
        smtp_port=server.port,
        default_sender="noreply@example.com",
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


class TestRealSmtpDelivery:
    @pytest.mark.asyncio
    async def test_a_confirmation_email_is_delivered(self, smtp, async_user):
        service = service_for(smtp)
        SurrealEngineAuth.configure_email_service(
            smtp_host="127.0.0.1", smtp_port=smtp.port
        )

        sent = await service.send_confirmation_email(
            async_user, "https://example.com/confirm/abc123"
        )

        assert sent is True
        message = smtp.last_message()
        assert message["To"] == "alice@example.com"
        assert message["Subject"] == "Confirm Your Account"
        text, html = smtp.bodies(message)
        assert "https://example.com/confirm/abc123" in text
        assert "https://example.com/confirm/abc123" in html

    @pytest.mark.asyncio
    async def test_a_two_factor_code_is_delivered_and_works(
        self, smtp, async_user
    ):
        service = service_for(smtp)
        SurrealEngineAuth.configure_email_service(
            smtp_host="127.0.0.1", smtp_port=smtp.port
        )
        async_user.tf_primary_method = "email"
        await async_user.save()

        sent = await service.send_two_factor_code(
            async_user, "123456", expires_in=300
        )

        assert sent is True
        message = smtp.last_message()
        assert message["Subject"] == "Your Two-Factor Authentication Code"
        text, html = smtp.bodies(message)
        assert "123456" in text
        assert "123456" in html
        # The lifetime is rendered, so the message cannot claim a window the
        # code was not actually issued with.
        assert "5" in text

    @pytest.mark.asyncio
    async def test_the_delivered_code_is_the_one_that_verifies(
        self, smtp, async_user
    ):
        """The code in the inbox must be the code the store accepts."""
        service = service_for(smtp)
        SurrealEngineAuth.configure_email_service(
            smtp_host="127.0.0.1", smtp_port=smtp.port
        )
        async_user.tf_primary_method = "email"
        await async_user.save()

        code = async_user.issue_email_two_factor_code()
        await service.send_two_factor_code(
            async_user, code, expires_in=async_user.email_code_expires_in
        )

        text, _ = smtp.bodies(smtp.last_message())
        assert code in text
        # And it verifies through the public API.
        assert await async_user.verify_two_factor_async(code)

    @pytest.mark.asyncio
    async def test_a_passwordless_link_is_delivered(self, smtp, async_user):
        service = service_for(smtp)
        SurrealEngineAuth.configure_email_service(
            smtp_host="127.0.0.1", smtp_port=smtp.port
        )

        sent = await service.send_passwordless_login_link(
            async_user, "https://example.com/login/xyz"
        )

        assert sent is True
        text, _ = smtp.bodies(smtp.last_message())
        assert "https://example.com/login/xyz" in text

    def test_the_sync_path_reaches_the_server(self, smtp, user):
        service = service_for(smtp)

        sent = service.send_confirmation_email_sync(
            user, "https://example.com/confirm/sync"
        )

        assert sent is True
        text, _ = smtp.bodies(smtp.last_message())
        assert "https://example.com/confirm/sync" in text

    @pytest.mark.asyncio
    async def test_a_rejected_recipient_is_reported_as_failure(
        self, smtp_rejecting, async_user
    ):
        service = service_for(smtp_rejecting)

        sent = await service.send_confirmation_email(
            async_user, "https://example.com/confirm/abc"
        )

        assert sent is False

    @pytest.mark.asyncio
    async def test_authentication_succeeds_when_the_server_wants_it(
        self, smtp_auth, async_user
    ):
        service = service_for(
            smtp_auth, smtp_username="user", smtp_password="pass"
        )

        sent = await service.send_confirmation_email(
            async_user, "https://example.com/confirm/abc"
        )

        assert sent is True
        assert smtp_auth.authenticated is True

    @pytest.mark.asyncio
    async def test_authentication_failure_is_reported_as_failure(
        self, smtp_auth, async_user
    ):
        service = service_for(smtp_auth, smtp_username="user")

        sent = await service.send_confirmation_email(
            async_user, "https://example.com/confirm/abc"
        )

        assert sent is False


class TestServiceOverRealSmtp:
    @pytest.mark.asyncio
    async def test_send_two_factor_code_audits_the_send(self, smtp, async_user):
        SurrealEngineAuth.configure_email_service(
            smtp_host="127.0.0.1", smtp_port=smtp.port
        )
        async_user.tf_primary_method = "email"
        await async_user.save()

        assert await SurrealEngineAuth.send_two_factor_code_async(async_user)

        assert smtp.messages, "nothing was delivered"
        from surrealengine_auth.models import SecurityEvent

        events = await SecurityEvent.objects.filter(
            event_type="two_factor_code_sent", user_id=async_user.id
        ).all()
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_a_failed_send_is_audited_as_a_failure(
        self, smtp_rejecting, async_user
    ):
        SurrealEngineAuth.configure_email_service(
            smtp_host="127.0.0.1", smtp_port=smtp_rejecting.port
        )
        async_user.tf_primary_method = "email"
        await async_user.save()

        assert not await SurrealEngineAuth.send_two_factor_code_async(async_user)

        from surrealengine_auth.models import SecurityEvent

        events = await SecurityEvent.objects.filter(
            event_type="two_factor_code_send_failed", user_id=async_user.id
        ).all()
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_the_email_never_contains_a_credential(
        self, smtp, async_user
    ):
        """A delivered message must not leak the stored hash or a password."""
        service = service_for(smtp)
        SurrealEngineAuth.configure_email_service(
            smtp_host="127.0.0.1", smtp_port=smtp.port
        )
        async_user.tf_primary_method = "email"
        await async_user.save()
        code = async_user.issue_email_two_factor_code()

        await service.send_two_factor_code(async_user, code, expires_in=300)

        raw = smtp.messages[-1]
        assert async_user.password_hash not in raw
        assert async_user.tf_email_code_hash not in raw
        assert "correct horse battery staple" not in raw
