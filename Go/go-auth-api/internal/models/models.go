package models

import (
	"time"

	"gorm.io/datatypes"
)

// User (Baseado em app/models/user.py)
type User struct {
	ID                         uint           `gorm:"primarykey"`
	Email                      string         `gorm:"size:100;uniqueIndex;not null"`
	HashedPassword             *string        `gorm:"size:255;nullable"` // Nullable para OAuth
	FullName                   *string        `gorm:"size:150"`
	IsActive                   bool           `gorm:"default:false;not null"`
	IsVerified                 bool           `gorm:"default:false;not null"`
	VerificationTokenHash      *string        `gorm:"size:255;index"`
	VerificationTokenExpires   *time.Time
	ResetPasswordTokenHash     *string        `gorm:"size:255;index"`
	ResetPasswordTokenExpires *time.Time
	FailedLoginAttempts        int            `gorm:"default:0;not null"`
	LockedUntil                *time.Time
	CustomClaims               datatypes.JSON `gorm:"nullable"`
	OtpSecret                  *string        `gorm:"size:64;nullable"`
	IsMfaEnabled               bool           `gorm:"default:false;not null"`
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
	
	// Relacionamentos
	RecoveryCodes []MFARecoveryCode `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
	TrustedDevices []TrustedDevice   `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
	RefreshTokens  []RefreshToken    `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
}

// RefreshToken (Baseado em app/models/refresh_token.py)
type RefreshToken struct {
	ID            uint      `gorm:"primarykey"`
	UserID        uint      `gorm:"not null;index:idx_refresh_tokens_user_hash"`
	TokenHash     string    `gorm:"size:255;uniqueIndex;not null;index:idx_refresh_tokens_user_hash"`
	ExpiresAt     time.Time `gorm:"not null"`
	CreatedAt     time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	IsRevoked     bool      `gorm:"default:false;not null"`
	IPAddress     *string   `gorm:"size:100;nullable"`
	UserAgent     *string   `gorm:"size:255;nullable"`
	
	User User `gorm:"foreignKey:UserID"`
}

// MFARecoveryCode (Baseado em app/models/mfa_recovery_code.py)
type MFARecoveryCode struct {
	ID          uint   `gorm:"primarykey"`
	UserID      uint   `gorm:"not null;index"`
	HashedCode  string `gorm:"size:255;not null;uniqueIndex"`
	IsUsed      bool   `gorm:"default:false;not null"`
	
	User User `gorm:"foreignKey:UserID"`
}

// TrustedDevice (Baseado em app/models/trusted_device.py)
type TrustedDevice struct {
	ID                uint       `gorm:"primarykey"`
	UserID            uint       `gorm:"not null;index"`
	DeviceTokenHash   string     `gorm:"size:255;uniqueIndex;not null"`
	UserAgent         *string    `gorm:"size:255;nullable"`
	IPAddress         *string    `gorm:"size:100;nullable"`
	Description       *string    `gorm:"size:255;nullable"`
	CreatedAt         time.Time  `gorm:"default:CURRENT_TIMESTAMP"`
	LastUsedAt        *time.Time `gorm:"nullable"`
	
	User User `gorm:"foreignKey:UserID"`
}