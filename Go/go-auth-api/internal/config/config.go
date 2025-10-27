package config

import (
	"log"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	DatabaseURL        string `mapstructure:"DATABASE_URL"`
	SecretKey          string `mapstructure:"SECRET_KEY"`
	RefreshSecretKey   string `mapstructure:"REFRESH_SECRET_KEY"`
	ResetPassSecretKey string `mapstructure:"RESET_PASSWORD_SECRET_KEY"`
	MFAChallengeSecret string `mapstructure:"MFA_CHALLENGE_SECRET_KEY"`
	InternalAPIKey     string `mapstructure:"INTERNAL_API_KEY"`

	AccessTokenExpireMinutes  time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRE_MINUTES"`
	RefreshTokenExpireDays    time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRE_DAYS"`
	EmailVerifyTokenMinutes   time.Duration `mapstructure:"EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES"`
	ResetPassTokenMinutes     time.Duration `mapstructure:"RESET_PASSWORD_TOKEN_EXPIRE_MINUTES"`
	MFAChallengeTokenMinutes  time.Duration `mapstructure:"MFA_CHALLENGE_EXPIRE_MINUTES"`
	TrustedDeviceCookieMaxAge time.Duration `mapstructure:"TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS"`

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
	// (Viper lida com a conversão de string para time.Duration para os minutos/dias)
	bindEnvs(v)

	// Carregar para a struct
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		log.Fatalf("Erro ao decodificar config: %v", err)
	}

	// Converter durações de minutos/dias para as unidades corretas (time.Duration)
	config.AccessTokenExpireMinutes = config.AccessTokenExpireMinutes * time.Minute
	config.RefreshTokenExpireDays = config.RefreshTokenExpireDays * 24 * time.Hour
	config.EmailVerifyTokenMinutes = config.EmailVerifyTokenMinutes * time.Minute
	config.ResetPassTokenMinutes = config.ResetPassTokenMinutes * time.Minute
	config.MFAChallengeTokenMinutes = config.MFAChallengeTokenMinutes * time.Minute
	config.TrustedDeviceCookieMaxAge = config.TrustedDeviceCookieMaxAge * 24 * time.Hour


	AppConfig = &config
	log.Println("Configuração carregada com sucesso.")
}

// bindEnvs garante que o Viper encontre as variáveis
func bindEnvs(v *viper.Viper) {
	v.BindEnv("DATABASE_URL")
	v.BindEnv("SECRET_KEY")
	v.BindEnv("REFRESH_SECRET_KEY")
	v.BindEnv("RESET_PASSWORD_SECRET_KEY")
	v.BindEnv("MFA_CHALLENGE_SECRET_KEY")
	v.BindEnv("INTERNAL_API_KEY")
	v.BindEnv("ACCESS_TOKEN_EXPIRE_MINUTES")
	v.BindEnv("REFRESH_TOKEN_EXPIRE_DAYS")
	v.BindEnv("EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES")
	v.BindEnv("RESET_PASSWORD_TOKEN_EXPIRE_MINUTES")
	v.BindEnv("MFA_CHALLENGE_EXPIRE_MINUTES")
	v.BindEnv("TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS")
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