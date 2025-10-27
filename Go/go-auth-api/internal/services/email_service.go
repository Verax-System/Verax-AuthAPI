package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-auth-api/internal/config"
	"log"
	"net/http"
	"time"
)

const brevoAPIURL = "https://api.brevo.com/v3/smtp/email"

// BrevoPayload (baseado no JSON de email_service.py)
type BrevoPayload struct {
	Sender      BrevoSender      `json:"sender"`
	To          []BrevoRecipient `json:"to"`
	Subject     string           `json:"subject"`
	HTMLContent string           `json:"htmlContent"`
}
type BrevoSender struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}
type BrevoRecipient struct {
	Email string `json:"email"`
}

// sendEmailHttpAPI (porta do Python)
func sendEmailHttpAPI(emailTo, subject, htmlContent string) (bool, error) {
	cfg := config.AppConfig
	if cfg.BrevoAPIKey == "" {
		log.Println("ERRO: BREVO_API_KEY não configurada. Email não será enviado.")
		return false, fmt.Errorf("BREVO_API_KEY não configurada")
	}

	payload := BrevoPayload{
		Sender: BrevoSender{
			Name:  cfg.EmailFromName,
			Email: cfg.EmailFrom,
		},
		To: []BrevoRecipient{
			{Email: emailTo},
		},
		Subject:     subject,
		HTMLContent: htmlContent,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Erro ao serializar payload Brevo: %v", err)
		return false, err
	}

	req, err := http.NewRequest("POST", brevoAPIURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("Erro ao criar requisição Brevo: %v", err)
		return false, err
	}

	req.Header.Set("api-key", cfg.BrevoAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Erro ao enviar email para %s via Brevo: %v", emailTo, err)
		return false, err
	}
	defer resp.Body.Close()

	// Brevo retorna 201 Created (como no Python)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("Email aceito para envio para %s via Brevo. Status: %d", emailTo, resp.StatusCode)
		return true, nil
	}

	log.Printf("Falha ao enviar email para %s. Status: %d", emailTo, resp.StatusCode)
	// (Opcional: ler o body da resposta para debug)
	return false, fmt.Errorf("falha no envio do email, status: %d", resp.StatusCode)
}

// SendVerificationEmail (porta do Python)
func SendVerificationEmail(emailTo, verificationToken string) {
	cfg := config.AppConfig
	projectName := cfg.EmailFromName
	subject := fmt.Sprintf("Bem-vindo(a) a %s! Confirme seu e-mail", projectName)
	verificationURL := fmt.Sprintf("%s/%s", cfg.VerifyURLBase, verificationToken)

	// (O HTML completo do Python deve ser colado aqui)
	htmlContent := fmt.Sprintf(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    ... (Cole o HTML gigante de email_service.py aqui) ...
    <a href="%s" target="_blank" ...>Verificar E-mail</a>
    ...
    <a href="%s" target="_blank" ...>%s</a>
    ...
    </html>
    `, verificationURL, verificationURL, verificationURL) // Substituir as variáveis

	// Envia em uma goroutine para não bloquear a resposta da API
	go func() {
		_, err := sendEmailHttpAPI(emailTo, subject, htmlContent)
		if err != nil {
			log.Printf("Falha ao enviar email de verificação (goroutine): %v", err)
		}
	}()
}

// SendPasswordResetEmail (porta do Python)
func SendPasswordResetEmail(emailTo, resetToken string) {
	cfg := config.AppConfig
	projectName := cfg.EmailFromName
	subject := fmt.Sprintf("%s - Redefinição de Senha", projectName)
	resetURL := fmt.Sprintf("%s/%s", cfg.ResetPassURLBase, resetToken)

	htmlContent := fmt.Sprintf(`
    <html><body>
        <p>Olá,</p>
        <p>Recebemos uma solicitação para redefinir sua senha em %s.</p>
        <p>Se foi você, clique no link abaixo para criar uma nova senha:</p>
        <p><a href="%s">%s</a></p>
        <p>Este link expirará em %d minutos.</p>
        <p>Se você não solicitou uma redefinição de senha, por favor ignore este e-mail.</p>
    </body></html>
    `, projectName, resetURL, resetURL, int(cfg.ResetPassTokenMinutes.Minutes()))

	// Envia em uma goroutine
	go func() {
		_, err := sendEmailHttpAPI(emailTo, subject, htmlContent)
		if err != nil {
			log.Printf("Falha ao enviar email de reset de senha (goroutine): %v", err)
		}
	}()
}