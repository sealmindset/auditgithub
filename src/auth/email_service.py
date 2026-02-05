"""
Email Service for Invitation System

Lightweight email sender using Python's built-in smtplib.
Supports both development (MailHog) and production (Gmail, SendGrid, etc.) SMTP servers.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from loguru import logger


class EmailService:
    """Lightweight email service for sending invitations."""

    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "1025"))  # MailHog default
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.smtp_from = os.getenv("SMTP_FROM", "noreply@auditgithub.local")
        self.use_tls = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
        self.use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
        self.app_url = os.getenv("APP_URL", "http://localhost:3000")

    def send_invitation_email(
        self,
        recipient_email: str,
        invite_token: str,
        inviter_name: str,
        role: str,
        access_type: str,
        expires_in_days: int = 7
    ) -> bool:
        """
        Send invitation email.

        Args:
            recipient_email: Email address to send invitation to
            invite_token: Unique invitation token
            inviter_name: Name of person who sent invite
            role: Role being assigned (e.g., 'admin', 'developer')
            access_type: Access type (e.g., 'ui_only', 'api_only', 'both')
            expires_in_days: Number of days until invitation expires

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            invitation_link = f"{self.app_url}/invite/{invite_token}"

            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "You've been invited to AuditGitHub"
            msg["From"] = self.smtp_from
            msg["To"] = recipient_email

            # Create plain text version
            text_content = self._create_text_email(
                recipient_email, invitation_link, inviter_name, role, access_type, expires_in_days
            )

            # Create HTML version
            html_content = self._create_html_email(
                recipient_email, invitation_link, inviter_name, role, access_type, expires_in_days
            )

            # Attach both versions
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            msg.attach(part1)
            msg.attach(part2)

            # Send email
            self._send_email(msg)

            logger.info(f"Invitation email sent to {recipient_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send invitation email to {recipient_email}: {e}")
            return False

    def _send_email(self, msg: MIMEMultipart):
        """Send email via SMTP."""
        if self.use_ssl:
            # Use SSL
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
        else:
            # Use TLS or no encryption (MailHog)
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

    def _create_text_email(
        self,
        recipient_email: str,
        invitation_link: str,
        inviter_name: str,
        role: str,
        access_type: str,
        expires_in_days: int
    ) -> str:
        """Create plain text email content."""
        role_display = role.replace('_', ' ').title()
        access_display = access_type.replace('_', ' ').title()

        return f"""
You've been invited to AuditGitHub!

{inviter_name} has invited you to join AuditGitHub, a security scanning and analysis platform.

Invitation Details:
- Email: {recipient_email}
- Role: {role_display}
- Access Type: {access_display}

To accept this invitation:
1. Click the link below
2. Sign in with your Microsoft account
3. Start using AuditGitHub

Invitation Link:
{invitation_link}

This invitation will expire in {expires_in_days} days.

---
AuditGitHub Security Platform
"""

    def _create_html_email(
        self,
        recipient_email: str,
        invitation_link: str,
        inviter_name: str,
        role: str,
        access_type: str,
        expires_in_days: int
    ) -> str:
        """Create HTML email content."""
        role_display = role.replace('_', ' ').title()
        access_display = access_type.replace('_', ' ').title()

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Invitation to AuditGitHub</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px 40px; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 12px 12px 0 0;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;">
                                🛡️ AuditGitHub
                            </h1>
                            <p style="margin: 8px 0 0 0; color: #e0e7ff; font-size: 14px;">
                                Security Scanning & Analysis Platform
                            </p>
                        </td>
                    </tr>

                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 16px 0; color: #1f2937; font-size: 24px; font-weight: 600;">
                                You've been invited!
                            </h2>
                            <p style="margin: 0 0 24px 0; color: #6b7280; font-size: 16px; line-height: 1.5;">
                                <strong>{inviter_name}</strong> has invited you to join <strong>AuditGitHub</strong>,
                                a comprehensive security scanning and analysis platform for your repositories.
                            </p>

                            <!-- Invitation Details Box -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 24px;">
                                <tr>
                                    <td style="padding: 20px;">
                                        <p style="margin: 0 0 12px 0; color: #6b7280; font-size: 14px;">
                                            <strong style="color: #374151;">Email:</strong> {recipient_email}
                                        </p>
                                        <p style="margin: 0 0 12px 0; color: #6b7280; font-size: 14px;">
                                            <strong style="color: #374151;">Role:</strong> {role_display}
                                        </p>
                                        <p style="margin: 0; color: #6b7280; font-size: 14px;">
                                            <strong style="color: #374151;">Access Type:</strong> {access_display}
                                        </p>
                                    </td>
                                </tr>
                            </table>

                            <!-- CTA Button -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                                <tr>
                                    <td align="center">
                                        <a href="{invitation_link}" style="display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 6px rgba(102, 126, 234, 0.3);">
                                            Accept Invitation
                                        </a>
                                    </td>
                                </tr>
                            </table>

                            <!-- Instructions -->
                            <div style="background-color: #eff6ff; border-left: 4px solid #3b82f6; padding: 16px; border-radius: 4px; margin-bottom: 24px;">
                                <p style="margin: 0 0 12px 0; color: #1e40af; font-size: 14px; font-weight: 600;">
                                    To get started:
                                </p>
                                <ol style="margin: 0; padding-left: 20px; color: #1e3a8a; font-size: 14px; line-height: 1.6;">
                                    <li>Click the "Accept Invitation" button above</li>
                                    <li>Sign in with your Microsoft account</li>
                                    <li>Start scanning and analyzing your repositories</li>
                                </ol>
                            </div>

                            <!-- Expiration Notice -->
                            <p style="margin: 0; color: #9ca3af; font-size: 13px; line-height: 1.5;">
                                ⏰ This invitation will expire in <strong>{expires_in_days} days</strong>.
                            </p>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="padding: 24px 40px; background-color: #f9fafb; border-radius: 0 0 12px 12px; text-align: center; border-top: 1px solid #e5e7eb;">
                            <p style="margin: 0; color: #9ca3af; font-size: 12px;">
                                If you didn't expect this invitation, you can safely ignore this email.
                            </p>
                            <p style="margin: 8px 0 0 0; color: #d1d5db; font-size: 11px;">
                                © 2026 AuditGitHub Security Platform
                            </p>
                        </td>
                    </tr>
                </table>

                <!-- Alternative Link -->
                <table width="600" cellpadding="0" cellspacing="0" style="margin-top: 16px;">
                    <tr>
                        <td style="padding: 0 40px; text-align: center;">
                            <p style="margin: 0; color: #9ca3af; font-size: 12px; line-height: 1.5;">
                                If the button doesn't work, copy and paste this link into your browser:
                            </p>
                            <p style="margin: 8px 0 0 0; word-break: break-all;">
                                <a href="{invitation_link}" style="color: #667eea; font-size: 12px; text-decoration: none;">
                                    {invitation_link}
                                </a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""


# Global email service instance
email_service = EmailService()
