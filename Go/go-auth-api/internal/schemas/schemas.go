package schemas

import (
	"go-auth-api/internal/models"
	"time"
)

// --- Schemas de Utilizador (de app/schemas/user.py) ---

type UserCreate struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"` // Adicionar validação de força depois
	FullName string `json:"full_name"`
}

// UserUpdate: Campos permitidos para atualização via /users/me
type UserUpdate struct {
	FullName *string `json:"full_name"`
	Email    *string `json:"email" binding:"omitempty,email"`      // Opcional, validar formato email
	Password *string `json:"password" binding:"omitempty,min=8"` // Opcional, validar força minima
}


type UserResponse struct {
	ID           uint      `json:"id"`
	Email        string    `json:"email"`
	FullName     *string   `json:"full_name"`
	IsActive     bool      `json:"is_active"`
	IsVerified   bool	   `json:"is_verified"` // Adicionado
	IsMfaEnabled bool      `json:"is_mfa_enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// CustomClaims não é exposto por padrão por segurança/privacidade
}

// FormatUserResponse ajusta o modelo DB para a resposta da API
func FormatUserResponse(user *models.User) UserResponse {
	return UserResponse{
		ID:           user.ID,
		Email:        user.Email,
		FullName:     user.FullName,
		IsActive:     user.IsActive,
		IsVerified:   user.IsVerified, // Adicionado
		IsMfaEnabled: user.IsMfaEnabled,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

// --- Schemas de Token (de app/schemas/token.py) ---

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type MFARequiredResponse struct {
	Detail            string `json:"detail"` // Ex: "MFA verification required"
	MFAChallengeToken string `json:"mfa_challenge_token"`
}

type GoogleLoginRequest struct {
	Code string `json:"code" binding:"required"`
}

type GoogleLoginUrlResponse struct {
	URL string `json:"url"`
}

// --- Schemas de Auth/MFA (de app/schemas/user.py) ---

// LoginRequest mapeia os campos do form OAuth2PasswordRequestForm
type LoginRequest struct {
	Username string `form:"username" binding:"required"` // Email
	Password string `form:"password" binding:"required"`
	Scope    string `form:"scope"` // Opcional para pedir custom claims
}


type MFAEnableResponse struct {
	OTPUri        string `json:"otp_uri"`
	QRCodeBase64  string `json:"qr_code_base64"`
}

type MFAConfirmRequest struct {
	OTPCode string `json:"otp_code" binding:"required,len=6,numeric"` // Validação Gin
}

type MFAConfirmResponse struct {
	User          UserResponse `json:"user"`
	RecoveryCodes []string     `json:"recovery_codes"`
}

type MFADisableRequest struct {
	OTPCode string `json:"otp_code" binding:"required,len=6,numeric"`
}

type MFAVerifyRequest struct {
	MFAChallengeToken string `json:"mfa_challenge_token" binding:"required"`
	OTPCode           string `json:"otp_code" binding:"required,len=6,numeric"`
}

type MFARecoveryRequest struct {
	MFAChallengeToken string `json:"mfa_challenge_token" binding:"required"`
	RecoveryCode      string `json:"recovery_code" binding:"required"` // Adicionar validação de formato se desejar
}

// --- Schemas de Sessão/Dispositivo (de token.py e trusted_device.py) ---

type SessionInfo struct {
	ID        uint      `json:"id"`
	UserAgent *string   `json:"user_agent"`
	IPAddress *string   `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TrustedDeviceInfo struct {
	ID          uint       `json:"id"`
	Description *string    `json:"description"`
	IPAddress   *string    `json:"ip_address"`
	UserAgent   *string    `json:"user_agent"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
}

// --- Outros (Reset de Senha) ---
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"` // Adicionar validação de força depois
}