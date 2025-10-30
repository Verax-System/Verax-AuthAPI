package config

import (
	"log"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// Config struct updated to read durations as int first
type Config struct {
	DatabaseURL        string `mapstructure:"DATABASE_URL"`
	SecretKey          string `mapstructure:"SECRET_KEY"`
	RefreshSecretKey   string `mapstructure:"REFRESH_SECRET_KEY"`
	ResetPassSecretKey string `mapstructure:"RESET_PASSWORD_SECRET_KEY"`
	MFAChallengeSecret string `mapstructure:"MFA_CHALLENGE_SECRET_KEY"`
	InternalAPIKey     string `mapstructure:"INTERNAL_API_KEY"`

	// Read durations as integers first
	AccessTokenExpireMinutesInt  int `mapstructure:"ACCESS_TOKEN_EXPIRE_MINUTES"`
	RefreshTokenExpireDaysInt    int `mapstructure:"REFRESH_TOKEN_EXPIRE_DAYS"`
	EmailVerifyTokenMinutesInt   int `mapstructure:"EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES"`
	ResetPassTokenMinutesInt     int `mapstructure:"RESET_PASSWORD_TOKEN_EXPIRE_MINUTES"`
	MFAChallengeTokenMinutesInt  int `mapstructure:"MFA_CHALLENGE_EXPIRE_MINUTES"`
	TrustedDeviceCookieMaxAgeInt int `mapstructure:"TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS"`

	// Fields to hold the final time.Duration values (not mapped directly)
	AccessTokenExpireMinutes  time.Duration `mapstructure:"-"`
	RefreshTokenExpireDays    time.Duration `mapstructure:"-"`
	EmailVerifyTokenMinutes   time.Duration `mapstructure:"-"`
	ResetPassTokenMinutes     time.Duration `mapstructure:"-"`
	MFAChallengeTokenMinutes  time.Duration `mapstructure:"-"`
	TrustedDeviceCookieMaxAge time.Duration `mapstructure:"-"`

	BrevoAPIKey     string `mapstructure:"BREVO_API_KEY"`
	EmailFrom       string `mapstructure:"EMAIL_FROM"`
	EmailFromName   string `mapstructure:"EMAIL_FROM_NAME"`
	VerifyURLBase   string `mapstructure:"VERIFICATION_URL_BASE"`
	ResetPassURLBase string `mapstructure:"RESET_PASSWORD_URL_BASE"`

	GoogleClientID     string `mapstructure:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `mapstructure:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURI  string `mapstructure:"GOOGLE_REDIRECT_URI_FRONTEND"`

	MaxFailedLogins int `mapstructure:"LOGIN_MAX_FAILED_ATTEMPTS"`
	LockoutMinutes  int `mapstructure:"LOGIN_LOCKOUT_MINUTES"`

	JWTIssuer    string `mapstructure:"JWT_ISSUER"`
	JWTAudience  string `mapstructure:"JWT_AUDIENCE"`
	CookieName   string `mapstructure:"TRUSTED_DEVICE_COOKIE_NAME"`
}

var AppConfig *Config

func LoadConfig() {
	// Carrega o .env primeiro (útil para desenvolvimento local fora do Docker)
	err := godotenv.Load()
	if err != nil {
		log.Println("Aviso: Não foi possível carregar o arquivo .env. Usando variáveis de ambiente.")
	}

	v := viper.New()
	v.AutomaticEnv() // Lê variáveis de ambiente

	// Bind das variáveis de ambiente para a struct
	bindEnvs(v)

	// Carregar para a struct (agora lê os ints)
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		log.Fatalf("Erro ao decodificar config: %v", err)
	}

	// Converter manualmente os inteiros lidos para time.Duration
	config.AccessTokenExpireMinutes = time.Duration(config.AccessTokenExpireMinutesInt) * time.Minute
	config.RefreshTokenExpireDays = time.Duration(config.RefreshTokenExpireDaysInt) * 24 * time.Hour
	config.EmailVerifyTokenMinutes = time.Duration(config.EmailVerifyTokenMinutesInt) * time.Minute
	config.ResetPassTokenMinutes = time.Duration(config.ResetPassTokenMinutesInt) * time.Minute
	config.MFAChallengeTokenMinutes = time.Duration(config.MFAChallengeTokenMinutesInt) * time.Minute
	config.TrustedDeviceCookieMaxAge = time.Duration(config.TrustedDeviceCookieMaxAgeInt) * 24 * time.Hour


	AppConfig = &config
	log.Println("Configuração carregada com sucesso.")
}

// bindEnvs garante que o Viper encontre as variáveis
// (Needs to bind the _INT versions now)
func bindEnvs(v *viper.Viper) {
	v.BindEnv("DATABASE_URL")
	v.BindEnv("SECRET_KEY")
	v.BindEnv("REFRESH_SECRET_KEY")
	v.BindEnv("RESET_PASSWORD_SECRET_KEY")
	v.BindEnv("MFA_CHALLENGE_SECRET_KEY")
	v.BindEnv("INTERNAL_API_KEY")
	// Bind the integer versions
	v.BindEnv("ACCESS_TOKEN_EXPIRE_MINUTES")
	v.BindEnv("REFRESH_TOKEN_EXPIRE_DAYS")
	v.BindEnv("EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES")
	v.BindEnv("RESET_PASSWORD_TOKEN_EXPIRE_MINUTES")
	v.BindEnv("MFA_CHALLENGE_EXPIRE_MINUTES")
	v.BindEnv("TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS")
	// Continue binding others
	v.BindEnv("BREVO_API_KEY")
	v.BindEnv("EMAIL_FROM")
	v.BindEnv("EMAIL_FROM_NAME")
	v.BindEnv("VERIFICATION_URL_BASE")
	v.BindEnv("RESET_PASSWORD_URL_BASE")
	v.BindEnv("GOOGLE_CLIENT_ID")
	v.BindEnv("GOOGLE_CLIENT_SECRET")
	v.BindEnv("GOOGLE_REDIRECT_URI_FRONTEND")
	v.BindEnv("LOGIN_MAX_FAILED_ATTEMPTS")
	v.BindEnv("LOGIN_LOCKOUT_MINUTES")
	v.BindEnv("JWT_ISSUER")
	v.BindEnv("JWT_AUDIENCE")
	v.BindEnv("TRUSTED_DEVICE_COOKIE_NAME")
}