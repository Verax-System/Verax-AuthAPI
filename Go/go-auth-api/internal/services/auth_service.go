package services

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"go-auth-api/internal/config"
	"go-auth-api/internal/models"
	"image/png"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// --- Hashing (de security.py) ---

func HashPassword(password string) (string, error) {
	// Limita a 72 bytes como no Python
	if len(password) > 72 {
		password = password[:72]
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func VerifyPassword(password, hash string) bool {
	if len(password) > 72 {
		password = password[:72]
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Reutiliza para recovery codes
var HashRecoveryCode = HashPassword
var VerifyRecoveryCode = VerifyPassword

// --- Hashing de Token (de crud_refresh_token.py e crud_trusted_device.py) ---

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash)
}

// --- Funções de Token JWT (de security.py) ---

// CustomClaims para Access Token (replicando OIDC)
type AccessTokenClaims struct {
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	AMR           []string `json:"amr"` // Authentication Methods Reference
	Name          *string  `json:"name,omitempty"`
	// Adiciona claims customizados dinamicamente
	CustomClaims map[string]interface{} `json:"-"` // Para mesclar
	jwt.RegisteredClaims
}

func CreateAccessToken(user *models.User, mfaPassed bool, requestedScopes []string) (string, error) {
	cfg := config.AppConfig
	expirationTime := time.Now().Add(cfg.AccessTokenExpireMinutes)
	
	amr := []string{"pwd"}
	if user.IsMfaEnabled && mfaPassed {
		amr = []string{"pwd", "mfa"}
	}

	claims := &AccessTokenClaims{
		Email:         user.Email,
		EmailVerified: user.IsVerified,
		AMR:           amr,
		Name:          user.FullName,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.JWTIssuer,
			Audience:  jwt.ClaimStrings{cfg.JWTAudience},
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprint(user.ID),
		},
	}

	// Adicionar custom claims baseados nos scopes
	// (Precisa implementar a lógica de parsing do user.CustomClaims)

	// Criar o token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.SecretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Claims para Refresh Token (mais simples)
type RefreshTokenClaims struct {
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func CreateRefreshToken(userID uint) (string, time.Time, error) {
	cfg := config.AppConfig
	expirationTime := time.Now().Add(cfg.RefreshTokenExpireDays)

	claims := &RefreshTokenClaims{
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.JWTIssuer,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Subject:   fmt.Sprint(userID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.RefreshSecretKey))
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expirationTime, nil
}

func ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.AppConfig.RefreshSecretKey), nil
	}, jwt.WithIssuer(config.AppConfig.JWTIssuer))

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("token inválido")
	}
	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("tipo de token inválido")
	}
	return claims, nil
}

// Claims para Tokens Especiais (MFA, Reset de Senha, etc.)
type SpecialTokenClaims struct {
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func createSpecialToken(userID uint, tokenType string, duration time.Duration, secretKey string) (string, time.Time, error) {
	cfg := config.AppConfig
	expirationTime := time.Now().Add(duration)

	claims := &SpecialTokenClaims{
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.JWTIssuer,
			Audience:  jwt.ClaimStrings{cfg.JWTAudience},
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprint(userID),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expirationTime, nil
}

func validateSpecialToken(tokenString, expectedType, secretKey string) (*SpecialTokenClaims, error) {
	claims := &SpecialTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	}, jwt.WithIssuer(config.AppConfig.JWTIssuer), jwt.WithAudience(config.AppConfig.JWTAudience))

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("token inválido")
	}
	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("tipo de token incorreto")
	}
	return claims, nil
}

// Wrappers para MFA Challenge Token (de auth.py)
func CreateMFAChallengeToken(userID uint) (string, error) {
	cfg := config.AppConfig
	token, _, err := createSpecialToken(userID, "mfa_challenge", cfg.MFAChallengeTokenMinutes, cfg.MFAChallengeSecret)
	return token, err
}

func ValidateMFAChallengeToken(tokenString string) (string, error) {
	claims, err := validateSpecialToken(tokenString, "mfa_challenge", config.AppConfig.MFAChallengeSecret)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// Wrappers para Password Reset Token (de security.py)
func CreatePasswordResetToken(email string, userID uint) (string, time.Time, error) {
	cfg := config.AppConfig
	// O token de reset usa o Subject (ID) para lookup, mas guardamos o email no Issuer/Audience se quisermos
	// Vamos manter simples e usar o Subject para ID, como os outros.
	token, expires, err := createSpecialToken(userID, "password_reset", cfg.ResetPassTokenMinutes, cfg.ResetPassSecretKey)
	return token, expires, err
}

func ValidatePasswordResetToken(tokenString string) (string, error) {
	claims, err := validateSpecialToken(tokenString, "password_reset", config.AppConfig.ResetPassSecretKey)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}


// --- Funções MFA/OTP (de security.py) ---

func GenerateOTP() (*totp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      config.AppConfig.EmailFromName,
		AccountName: "", // Será definido por usuário
		Period:      30,
		SecretSize:  20, // Padrão
	})
}

func GenerateOTPAuthURL(key *totp.Key, email string) string {
	// Atualiza o AccountName no URI
	return strings.Replace(key.URL(), "user@example.com", email, 1)
}

func ValidateOTP(secret string, code string) bool {
	if secret == "" {
		return false
	}
	// 'valid_window=1' do Python é 1*30s = 30s.
	// O padrão do 'totp.Validate' já permite 30s de drift (skew=1).
	valid := totp.Validate(code, secret)
	return valid
}

func GenerateQRCodeBase64(otpURI string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.AppConfig.EmailFromName,
		AccountName: "temp", // Placeholder, pois vamos usar a URI
	})
	if err != nil {
		return "", err
	}
	
	// Analisa a URI para obter a imagem
	img, err := key.Image(200, 200) // (size, size)
	if err != nil {
		// Tentar de novo com a URI analisada (workaround)
		key, err = totp.Generate(totp.GenerateOpts{})
		if err != nil { return "", err }
		img, err = key.Image(200, 200)
		if err != nil {
			log.Printf("Erro ao gerar QR Code: %v", err)
			return "", err
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// --- Funções de Recovery Code (de crud_mfa_recovery_code.py) ---

const (
	NumberOfRecoveryCodes = 10
	RecoveryCodeLength    = 3 // 3 hex = 6 chars (abc-def)
)

func GeneratePlainRecoveryCodes() []string {
	codes := make([]string, NumberOfRecoveryCodes)
	for i := 0; i < NumberOfRecoveryCodes; i++ {
		b1 := make([]byte, RecoveryCodeLength)
		b2 := make([]byte, RecoveryCodeLength)
		rand.Read(b1)
		rand.Read(b2)
		codes[i] = fmt.Sprintf("%x-%x", b1, b2)
	}
	return codes
}