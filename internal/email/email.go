package email

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// Config holds SMTP connection settings.
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
	UseTLS   bool // true = implicit TLS on connect (port 465); false = STARTTLS (port 587) or plain
}

// Enabled reports whether SMTP is configured.
func (c Config) Enabled() bool { return c.Host != "" }

// SendPasswordReset sends a password reset email to the given address.
func SendPasswordReset(cfg Config, to, resetURL string) error {
	subject := "Password Reset Request"
	body := fmt.Sprintf(`You requested a password reset for your Penkeeper account.

Click the link below to set a new password. This link expires in 1 hour and can only be used once.

%s

If you did not request a password reset, please ignore this email.
`, resetURL)

	msg := buildMessage(cfg.From, to, subject, body)

	if cfg.UseTLS {
		return sendImplicitTLS(cfg, to, msg)
	}
	return sendSTARTTLS(cfg, to, msg)
}

// sanitizeHeader removes CR and LF characters to prevent email header injection.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

// buildMessage constructs a minimal RFC 2822 email message.
func buildMessage(from, to, subject, body string) []byte {
	var sb strings.Builder
	sb.WriteString("From: " + sanitizeHeader(from) + "\r\n")
	sb.WriteString("To: " + sanitizeHeader(to) + "\r\n")
	sb.WriteString("Subject: " + sanitizeHeader(subject) + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return []byte(sb.String())
}

// sendSTARTTLS sends via STARTTLS (typical for port 587).
// smtp.SendMail automatically negotiates STARTTLS when the server advertises it.
func sendSTARTTLS(cfg Config, to string, msg []byte) error {
	addr := net.JoinHostPort(cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.User, cfg.Password, cfg.Host)
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, msg)
}

// sendImplicitTLS sends via implicit TLS (port 465).
func sendImplicitTLS(cfg Config, to string, msg []byte) error {
	addr := net.JoinHostPort(cfg.Host, cfg.Port)
	tlsCfg := &tls.Config{ServerName: cfg.Host}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	auth := smtp.PlainAuth("", cfg.User, cfg.Password, cfg.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	return w.Close()
}
