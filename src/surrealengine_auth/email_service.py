from typing import Dict, Any, Optional, List, Union
import os
import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path

class EmailService:
    """
    Service for sending emails using Jinja2 templates.
    """
    
    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        smtp_username: Optional[str] = None,
        smtp_password: Optional[str] = None,
        use_tls: bool = False,
        use_ssl: bool = False,
        default_sender: str = "noreply@example.com",
        templates_dir: Optional[str] = None
    ):
        """
        Initialize the email service.
        
        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_username: SMTP username (if authentication is required)
            smtp_password: SMTP password (if authentication is required)
            use_tls: Whether to use STARTTLS
            use_ssl: Whether to use SSL/TLS
            default_sender: Default sender email address
            templates_dir: Directory containing email templates
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.default_sender = default_sender
        
        # Set up Jinja2 environment
        if templates_dir is None:
            # Use default templates directory
            templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        
        # Create templates directory if it doesn't exist
        Path(templates_dir).mkdir(parents=True, exist_ok=True)
        
        self.env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    async def send_email(
        self,
        recipient: str,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        sender: Optional[str] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None
    ) -> bool:
        """
        Send an email using a template.
        
        Args:
            recipient: Recipient email address
            subject: Email subject
            template_name: Name of the template to use
            context: Context variables for the template
            sender: Sender email address (defaults to self.default_sender)
            cc: List of CC recipients
            bcc: List of BCC recipients
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        if sender is None:
            sender = self.default_sender
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient
        
        if cc:
            msg['Cc'] = ', '.join(cc)
        if bcc:
            msg['Bcc'] = ', '.join(bcc)
        
        # Render templates
        try:
            # Try to render both HTML and text templates
            html_template = self.env.get_template(f"{template_name}.html")
            text_template = self.env.get_template(f"{template_name}.txt")
            
            html_content = html_template.render(**context)
            text_content = text_template.render(**context)
            
            # Attach parts
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
        except Exception as e:
            # If template not found or rendering fails, use a simple text message
            print(f"Template rendering error: {e}")
            msg.attach(MIMEText(f"Error rendering template: {e}", 'plain'))
            return False
        
        # Send email
        try:
            recipients = [recipient]
            if cc:
                recipients.extend(cc)
            if bcc:
                recipients.extend(bcc)
                
            await aiosmtplib.send(
                message=msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_username,
                password=self.smtp_password,
                use_tls=self.use_tls,
                start_tls=self.use_tls and not self.use_ssl,
                validate_certs=True,
                sender=sender,
                recipients=recipients
            )
            return True
        except Exception as e:
            print(f"Email sending error: {e}")
            return False
    
    def send_email_sync(
        self,
        recipient: str,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        sender: Optional[str] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None
    ) -> bool:
        """
        Synchronous version of send_email.
        """
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            # If no event loop is available, create a new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.send_email(recipient, subject, template_name, context, sender, cc, bcc)
        )
    
    async def send_confirmation_email(self, user, confirmation_link: str) -> bool:
        """
        Send an account confirmation email.
        
        Args:
            user: User object
            confirmation_link: Link for confirming the account
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        return await self.send_email(
            recipient=user.email,
            subject="Confirm Your Account",
            template_name="confirmation",
            context={
                "user": user,
                "confirmation_link": confirmation_link
            }
        )
    
    async def send_two_factor_code(self, user, code: str) -> bool:
        """
        Send a two-factor authentication code via email.
        
        Args:
            user: User object
            code: Two-factor authentication code
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        return await self.send_email(
            recipient=user.email,
            subject="Your Two-Factor Authentication Code",
            template_name="two_factor",
            context={
                "user": user,
                "code": code
            }
        )
    
    async def send_passwordless_login_link(self, user, login_link: str) -> bool:
        """
        Send a passwordless login link via email.
        
        Args:
            user: User object
            login_link: Link for passwordless login
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        return await self.send_email(
            recipient=user.email,
            subject="Your Login Link",
            template_name="passwordless_login",
            context={
                "user": user,
                "login_link": login_link
            }
        )
    
    def send_confirmation_email_sync(self, user, confirmation_link: str) -> bool:
        """Synchronous version of send_confirmation_email."""
        return self.send_email_sync(
            recipient=user.email,
            subject="Confirm Your Account",
            template_name="confirmation",
            context={
                "user": user,
                "confirmation_link": confirmation_link
            }
        )
    
    def send_two_factor_code_sync(self, user, code: str) -> bool:
        """Synchronous version of send_two_factor_code."""
        return self.send_email_sync(
            recipient=user.email,
            subject="Your Two-Factor Authentication Code",
            template_name="two_factor",
            context={
                "user": user,
                "code": code
            }
        )
    
    def send_passwordless_login_link_sync(self, user, login_link: str) -> bool:
        """Synchronous version of send_passwordless_login_link."""
        return self.send_email_sync(
            recipient=user.email,
            subject="Your Login Link",
            template_name="passwordless_login",
            context={
                "user": user,
                "login_link": login_link
            }
        )