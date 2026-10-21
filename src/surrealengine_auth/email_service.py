"""
SMTP delivery for the authentication emails.

Templates live in ``templates/`` and are rendered with Jinja2 with autoescaping
on for HTML, so a username or email address containing markup cannot inject
into a message body.

Transport notes
---------------
* ``use_ssl`` selects implicit TLS (typically port 465) and ``use_tls``
  selects STARTTLS on a plaintext connection (typically port 587). 0.1.x passed
  ``use_tls`` to *both* ``use_tls`` and ``start_tls``, which aiosmtplib
  rejects, and never enabled implicit TLS at all.
* ``send_email_sync`` refuses to run inside a live event loop instead of
  raising a confusing "loop already running" error. Async applications should
  call the ``async`` methods.
"""

from __future__ import annotations

import asyncio
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .logger import get_logger


def _as_minutes(expires_in: Optional[int]) -> Optional[int]:
    """Whole minutes for a seconds-based lifetime, rounded up.

    Rounding up keeps the message from promising a window shorter than the
    one the code actually has. Returns None when unknown, which the templates
    render as an unstated expiry rather than a wrong one.
    """
    if expires_in is None:
        return None
    return max(1, -(-int(expires_in) // 60))

__all__ = ["EmailService"]


class EmailService:
    """Render templates and hand the result to an SMTP server."""

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        smtp_username: Optional[str] = None,
        smtp_password: Optional[str] = None,
        use_tls: bool = False,
        use_ssl: bool = False,
        default_sender: str = "noreply@example.com",
        templates_dir: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        """Configure the service.

        Args:
            smtp_host: SMTP server hostname.
            smtp_port: SMTP server port.
            smtp_username: SMTP username, if the server requires one.
            smtp_password: SMTP password.
            use_tls: Issue STARTTLS after connecting.
            use_ssl: Connect with implicit TLS.
            default_sender: Envelope and header sender.
            templates_dir: Directory holding the Jinja templates.
            timeout: Socket timeout in seconds.
        """
        if use_tls and use_ssl:
            raise ValueError(
                "use_tls (STARTTLS) and use_ssl (implicit TLS) are mutually "
                "exclusive"
            )

        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.default_sender = default_sender
        self.timeout = timeout
        self.logger = get_logger()

        if templates_dir is None:
            templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        if not os.path.isdir(templates_dir):
            raise FileNotFoundError(f"templates directory not found: {templates_dir}")

        self.env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    # ------------------------------------------------------------------ #
    # Sending
    # ------------------------------------------------------------------ #

    def _render(self, template_name: str, context: Dict[str, Any]) -> Dict[str, str]:
        """Render the ``.txt``/``.html`` pair for ``template_name``."""
        html = self.env.get_template(f"{template_name}.html").render(**context)
        text = self.env.get_template(f"{template_name}.txt").render(**context)
        return {"html": html, "text": text}

    def _build_message(
        self,
        recipient: str,
        subject: str,
        rendered: Dict[str, str],
        sender: str,
        cc: Optional[List[str]],
        bcc: Optional[List[str]],
    ) -> MIMEMultipart:
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = sender
        message["To"] = recipient
        if cc:
            message["Cc"] = ", ".join(cc)
        if bcc:
            message["Bcc"] = ", ".join(bcc)
        message.attach(MIMEText(rendered["text"], "plain"))
        message.attach(MIMEText(rendered["html"], "html"))
        return message

    async def send_email(
        self,
        recipient: str,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        sender: Optional[str] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
    ) -> bool:
        """Render and send one message.

        Returns True when the SMTP server accepted it. Failures are logged and
        reported as False; the caller decides whether that is fatal.
        """
        sender = sender or self.default_sender

        try:
            rendered = self._render(template_name, context)
        except Exception as exc:
            # Log the detail, but keep it out of the message: 0.1.x attached
            # the Jinja error to the outgoing body, which leaked template
            # paths to the recipient.
            self.logger.error(f"Template rendering failed for {template_name}: {exc}")
            return False

        message = self._build_message(recipient, subject, rendered, sender, cc, bcc)
        recipients = [recipient, *(cc or []), *(bcc or [])]

        try:
            # The message is passed positionally. aiosmtplib 4.0 made
            # positional arguments positional-only, so `message=message`
            # raises TypeError on every call -- and the exception is
            # swallowed below, so every send silently failed and returned
            # False. 0.1.x had the same call and the same bug.
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_username,
                password=self.smtp_password,
                use_tls=self.use_ssl,
                start_tls=self.use_tls,
                validate_certs=True,
                timeout=self.timeout,
                sender=sender,
                recipients=recipients,
            )
            return True
        except Exception as exc:
            self.logger.error(f"Email delivery failed to {recipient}: {exc}")
            return False

    def send_email_sync(
        self,
        recipient: str,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        sender: Optional[str] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
    ) -> bool:
        """Blocking wrapper around :meth:`send_email`.

        Raises:
            RuntimeError: when called from inside a running event loop, where
                there is no way to block. Use :meth:`send_email` there.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "send_email_sync() cannot run inside an event loop; "
                "await EmailService.send_email() instead"
            )

        return asyncio.run(
            self.send_email(recipient, subject, template_name, context, sender, cc, bcc)
        )

    # ------------------------------------------------------------------ #
    # Auth-specific messages
    # ------------------------------------------------------------------ #

    async def send_confirmation_email(self, user, confirmation_link: str) -> bool:
        """Send the address-confirmation link."""
        return await self.send_email(
            recipient=user.email,
            subject="Confirm Your Account",
            template_name="confirmation",
            context={"user": user, "confirmation_link": confirmation_link},
        )

    async def send_two_factor_code(
        self, user, code: str, expires_in: Optional[int] = None
    ) -> bool:
        """Send a 2FA code by email.

        ``expires_in`` is rendered into the message so the stated lifetime
        matches the one the code was actually issued with. A template that
        hardcodes "5 minutes" silently lies as soon as the lifetime is
        retuned.
        """
        return await self.send_email(
            recipient=user.email,
            subject="Your Two-Factor Authentication Code",
            template_name="two_factor",
            context={
                "user": user,
                "code": code,
                "expires_in": expires_in,
                "expires_minutes": _as_minutes(expires_in),
            },
        )

    async def send_passwordless_login_link(self, user, login_link: str) -> bool:
        """Send a passwordless login link."""
        return await self.send_email(
            recipient=user.email,
            subject="Your Login Link",
            template_name="passwordless_login",
            context={"user": user, "login_link": login_link},
        )

    def send_confirmation_email_sync(self, user, confirmation_link: str) -> bool:
        """Blocking :meth:`send_confirmation_email`."""
        return self.send_email_sync(
            recipient=user.email,
            subject="Confirm Your Account",
            template_name="confirmation",
            context={"user": user, "confirmation_link": confirmation_link},
        )

    def send_two_factor_code_sync(
        self, user, code: str, expires_in: Optional[int] = None
    ) -> bool:
        """Blocking :meth:`send_two_factor_code`."""
        return self.send_email_sync(
            recipient=user.email,
            subject="Your Two-Factor Authentication Code",
            template_name="two_factor",
            context={
                "user": user,
                "code": code,
                "expires_in": expires_in,
                "expires_minutes": _as_minutes(expires_in),
            },
        )

    def send_passwordless_login_link_sync(self, user, login_link: str) -> bool:
        """Blocking :meth:`send_passwordless_login_link`."""
        return self.send_email_sync(
            recipient=user.email,
            subject="Your Login Link",
            template_name="passwordless_login",
            context={"user": user, "login_link": login_link},
        )
