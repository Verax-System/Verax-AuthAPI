package schemas

import (
	"go-auth-api/internal/models"
	"time"
)

// --- Schemas de Usuário (de app/schemas/user.py) ---

type UserCreate struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	FullName string `json:"full_name"`
}

type UserResponse struct {
	ID          uint      `json:"id"`
	Email       string    `json:"email"`
	FullName    *string   `json:"full_name"`
	IsActive    bool      `json:"is_active"`
	IsMfaEnabled bool      `json:"is_mfa_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// CustomClaims não é exposto por padrão por segurança
}

func FormatUserResponse(user *models.User) UserResponse {
	return UserResponse{
		ID:           user.ID,
		Email:        user.Email,
		FullName:     user.FullName,
		IsActive:     user.IsActive,
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
	Detail            string `json:"detail"`
	MFAChallengeToken string `json:"mfa_challenge_token"`
}

type GoogleLoginRequest struct {
	Code string `json:"code" binding:"required"`
}

type GoogleLoginUrlResponse struct {
	URL string `json:"url"`
}

// --- Schemas de Auth/MFA (de app/schemas/user.py) ---

type LoginRequest struct {
	Username string `form:"username" binding:"required"` // Vem de OAuth2PasswordRequestForm
	Password string `form:"password" binding:"required"` // Vem de OAuth2PasswordRequestForm
	Scope    string `form:"scope"`                       // Vem de OAuth2PasswordRequestForm
}

type MFAEnableResponse struct {
	OTPUri        string `json:"otp_uri"`
	QRCodeBase64  string `json:"qr_code_base64"`
}

type MFAConfirmRequest struct {
	OTPCode string `json:"otp_code" binding:"required,len=6"`
}

type MFAConfirmResponse struct {
	User          UserResponse `json:"user"`
	RecoveryCodes []string     `json:"recovery_codes"`
}

type MFADisableRequest struct {
	OTPCode string `json:"otp_code" binding:"required,len=6"`
}

type MFAVerifyRequest struct {
	MFAChallengeToken string `json:"mfa_challenge_token" binding:"required"`
	OTPCode           string `json:"otp_code" binding:"required,len=6"`
}

type MFARecoveryRequest struct {
	MFAChallengeToken string `json:"mfa_challenge_token" binding:"required"`
	RecoveryCode      string `json:"recovery_code" binding:"required"`
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

// --- Outros ---
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}