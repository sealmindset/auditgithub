# Email Invitation System

Complete guide for sending and managing user invitations via email.

## Overview

The invitation system allows Admins and Super Admins to invite new users to AuditGitHub via email. Users receive a professional HTML email with a secure invitation link that expires in 7 days.

## Features

- **Secure Tokens**: Cryptographically secure 64-character tokens
- **7-Day Expiration**: Invitations automatically expire after 7 days
- **HTML Emails**: Beautiful, mobile-responsive email templates
- **Role Assignment**: Assign roles during invitation (Super Admin, Admin, Manager, Analyst, Developer, User)
- **Access Control**: Set access type (UI only, API only, or Both)
- **Development Testing**: MailHog for testing emails without sending real emails
- **Production Ready**: Supports Gmail, SendGrid, AWS SES, and any SMTP server

---

## Quick Start (Development)

### 1. Start MailHog

MailHog is included in docker-compose and will start automatically:

```bash
docker-compose up -d mailhog
```

Access the MailHog web UI at: **http://localhost:8025**

### 2. Send an Invitation

Via the Admin Panel UI:

1. Navigate to **Settings > Authentication & Authorization**
2. Click **"Go to Admin Panel"**
3. Click **"Send Invitation"**
4. Fill in:
   - Email address
   - Role (e.g., Developer, Analyst)
   - Access type (UI only, API only, or Both)
5. Click **"Send Invitation"**

Via API:

```bash
curl -X POST http://localhost:8000/api/invitations \
  -H "Content-Type: application/json" \
  -H "Cookie: session=your-session-cookie" \
  -d '{
    "email": "user@example.com",
    "role": "developer",
    "access_type": "both"
  }'
```

### 3. View the Email

1. Open MailHog UI: **http://localhost:8025**
2. Click on the invitation email
3. View the HTML email with the invitation link
4. Click the invitation link to test the flow

---

## Production Setup

### Option 1: Gmail SMTP

1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate App Password**:
   - Go to Google Account > Security > 2-Step Verification
   - Scroll to "App passwords"
   - Generate a password for "Mail"
3. **Update `.env`**:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
SMTP_FROM=your-email@gmail.com
SMTP_USE_TLS=true
SMTP_USE_SSL=false
APP_URL=https://your-production-domain.com
```

### Option 2: SendGrid

1. **Sign up** at https://sendgrid.com
2. **Create API Key** with "Mail Send" permissions
3. **Update `.env`**:

```env
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=your-sendgrid-api-key
SMTP_FROM=noreply@yourdomain.com
SMTP_USE_TLS=true
SMTP_USE_SSL=false
APP_URL=https://your-production-domain.com
```

### Option 3: AWS SES

1. **Verify email address** in AWS SES console
2. **Create SMTP credentials**
3. **Update `.env`**:

```env
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=your-ses-smtp-username
SMTP_PASSWORD=your-ses-smtp-password
SMTP_FROM=noreply@yourdomain.com
SMTP_USE_TLS=true
SMTP_USE_SSL=false
APP_URL=https://your-production-domain.com
```

---

## Invitation Flow

### 1. Admin Sends Invitation

Admin/Super Admin logs in and sends invitation via UI or API:

```
POST /api/invitations
{
  "email": "newuser@company.com",
  "role": "developer",
  "access_type": "both"
}
```

### 2. User Receives Email

User receives HTML email with:
- Invitation details (role, access type)
- Secure invitation link: `https://your-domain.com/invite/{token}`
- Expiration notice (7 days)
- "Accept Invitation" button

### 3. User Clicks Link

Link opens invitation acceptance page showing:
- Inviter's name
- Role being assigned
- Access type
- "Accept & Sign In with Microsoft" button

### 4. Entra ID Authentication

User is redirected to Microsoft Entra ID OAuth:
- User signs in with Microsoft account
- Email must match invitation email
- Upon success, user account is created

### 5. Account Created

- User record created with specified role and access
- Invitation marked as "accepted"
- User logged in and redirected to dashboard
- First login timestamp recorded

---

## Email Template

The system sends beautifully formatted HTML emails with:

- **Header**: Purple gradient banner with AuditGitHub logo
- **Invitation Details**: Email, role, and access type in formatted box
- **Call to Action**: Large "Accept Invitation" button
- **Instructions**: Step-by-step guide
- **Expiration Notice**: Clear 7-day expiration warning
- **Plain Text Fallback**: For email clients that don't support HTML

**Preview**: Check MailHog at http://localhost:8025 to see the template

---

## API Endpoints

### Send Invitation

```http
POST /api/invitations
Content-Type: application/json

{
  "email": "user@example.com",
  "role": "developer",
  "access_type": "both"
}
```

**Response**:
```json
{
  "message": "Invitation sent successfully",
  "invitation_id": "uuid",
  "invitation_link": "http://localhost:3000/invite/token",
  "expires_at": "2026-02-12T..."
}
```

### List Pending Invitations

```http
GET /api/invitations
```

**Response**:
```json
{
  "invitations": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "role": "developer",
      "access_type": "both",
      "invited_by": "admin@company.com",
      "status": "pending",
      "expires_at": "2026-02-12T...",
      "created_at": "2026-02-05T..."
    }
  ]
}
```

### Validate Invitation Token

```http
GET /api/invitations/validate/{token}
```

**Response**:
```json
{
  "valid": true,
  "email": "user@example.com",
  "role": "developer",
  "access_type": "both",
  "invited_by_name": "John Admin",
  "expires_at": "2026-02-12T..."
}
```

### Revoke Invitation

```http
DELETE /api/invitations/{invitation_id}
```

**Response**:
```json
{
  "message": "Invitation revoked successfully"
}
```

---

## Security Features

### Token Generation

- **Algorithm**: `secrets.token_urlsafe(48)` - generates 64-character URL-safe token
- **Entropy**: ~288 bits of entropy
- **Uniqueness**: Stored in database with unique constraint

### Email Verification

- User's Entra ID email **must match** invitation email
- Prevents token hijacking by verifying email ownership

### Expiration

- Invitations expire after **7 days**
- Expired invitations cannot be accepted
- Automatic cleanup of expired invitations

### One-Time Use

- Once accepted, invitation is marked as "accepted"
- Token cannot be reused
- Old pending invitations are revoked when sending new one to same email

### Admin Audit

- All invitation events logged to `auth_audit_log` table
- Tracks: who invited, who accepted, when, from what IP

---

## Troubleshooting

### Emails Not Sending

**Check MailHog is running**:
```bash
docker ps | grep mailhog
```

**Check MailHog logs**:
```bash
docker logs auditgh_mailhog
```

**Check API logs**:
```bash
docker logs auditgh_api | grep -i "invitation"
```

### Emails Go to Spam (Production)

1. **Set up SPF record** for your domain
2. **Set up DKIM** in your SMTP provider
3. **Set up DMARC** policy
4. **Use authenticated SMTP** (TLS enabled)
5. **Verify sender domain** with your SMTP provider

### Invitation Link Broken

**Check APP_URL** environment variable:
```bash
# Should match your domain
APP_URL=http://localhost:3000  # Development
APP_URL=https://audit.company.com  # Production
```

### Email Mismatch Error

User's Microsoft account email must **exactly match** the invitation email:
- Invitation sent to: `john.doe@company.com`
- User must sign in with: `john.doe@company.com`
- Not: `j.doe@company.com` or `john@company.com`

---

## MailHog Web UI

Access at: **http://localhost:8025**

Features:
- View all captured emails
- Search emails
- View HTML and plain text versions
- View email headers
- Delete emails
- Test email rendering

Perfect for development and testing without sending real emails!

---

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | `localhost` | SMTP server hostname |
| `SMTP_PORT` | `1025` | SMTP server port |
| `SMTP_USER` | `""` | SMTP username (empty for MailHog) |
| `SMTP_PASSWORD` | `""` | SMTP password (empty for MailHog) |
| `SMTP_FROM` | `noreply@auditgithub.local` | From email address |
| `SMTP_USE_TLS` | `false` | Enable STARTTLS |
| `SMTP_USE_SSL` | `false` | Enable SSL/TLS |
| `APP_URL` | `http://localhost:3000` | Base URL for invitation links |

### Docker Compose Ports

| Service | Port | Description |
|---------|------|-------------|
| MailHog SMTP | 1025 | SMTP server (internal) |
| MailHog Web UI | 8025 | Web interface |

---

## Related Documentation

- [RBAC Implementation](./RBAC_IMPLEMENTATION.md) - Complete RBAC system guide
- [Authentication Flow](./docs/authentication-flow.md) - Entra ID OAuth flow
- [Admin Panel Guide](./docs/admin-panel.md) - User management UI

---

## Support

For issues or questions:
- Check logs: `docker logs auditgh_api`
- Check MailHog UI: http://localhost:8025
- Review `.env` configuration
- Verify Entra ID app registration settings
