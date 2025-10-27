package handlers

import (
	"errors"
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"go-auth-api/internal/schemas"
	"go-auth-api/internal/services"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

// Helper para obter IP/UserAgent
func getSessionDetails(c *gin.Context) (ip string, ua string) {
	ip = c.ClientIP()
	ua = c.Request.UserAgent()
	return
}

func ForgotPassword(c *gin.Context) {
	var input schemas.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	db := database.DB
	var user models.User

	// Procurar utilizador pelo email
	err := db.Where("email = ?", input.Email).First(&user).Error
	// Resposta ambígua de propósito, mesmo que o utilizador não exista ou esteja inativo
	responseMsg := "If a user with that email exists and is active, a password reset link will be sent."

	if err == nil && user.IsActive {
		// Utilizador encontrado e ativo, gerar token e enviar email
		resetTokenPlain, errGen := services.GeneratePasswordResetToken(&user)
		if errGen != nil {
			// Logar o erro interno, mas retornar a mensagem ambígua
			log.Printf("Erro ao gerar token de reset para %s: %v", input.Email, errGen)
		} else {
			// Enviar email em background
			go services.SendPasswordResetEmail(user.Email, resetTokenPlain)
			log.Printf("Solicitação de reset de senha para: %s. Email enviado (em background).", user.Email)
		}
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		// Erro de DB ao procurar o utilizador
		log.Printf("Erro DB ao procurar email %s para forgot password: %v", input.Email, err)
		// Retornar a mensagem ambígua
	} else {
		// Utilizador não encontrado ou inativo
		log.Printf("Tentativa de forgot password para email não existente ou inativo: %s", input.Email)
		// Retornar a mensagem ambígua
	}

	// Sempre retorna 202 Accepted com a mensagem genérica
	c.JSON(http.StatusAccepted, gin.H{"msg": responseMsg})
}
// RefreshToken (porta de /refresh)
func RefreshToken(c *gin.Context) {
	var input schemas.RefreshTokenRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	credentialsException := gin.H{"detail": "Could not validate credentials"} // Mensagem padrão

	// 1. Validar o JWT do refresh token
	claims, err := services.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		log.Printf("Falha na validação do refresh token: %v", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}
	userIDStr := claims.Subject

	// 2. Verificar se o token (hash) existe no DB, não está revogado e não expirou
	tokenHash := services.HashToken(input.RefreshToken)
	dbToken, err := services.GetValidRefreshTokenByHash(tokenHash)
	if err != nil {
		log.Printf("Refresh token inválido (DB check) para user ID %s: %v", userIDStr, err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}

	// 3. Verificar se o User ID do token JWT corresponde ao do DB (segurança extra)
	if fmt.Sprint(dbToken.UserID) != userIDStr {
		log.Printf("ALERTA: User ID do refresh token JWT (%s) não corresponde ao do DB (%d)", userIDStr, dbToken.UserID)
		// Revogar o token suspeito por segurança?
		services.RevokeRefreshTokenByHash(tokenHash)
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}

	// 4. Revogar o refresh token antigo que foi usado
	revoked, errRevoke := services.RevokeRefreshTokenByHash(tokenHash)
	if errRevoke != nil {
		// Logar erro mas talvez continuar? Depende da política de segurança. Vamos parar por agora.
		log.Printf("Erro ao revogar refresh token antigo (hash: %s...) durante refresh: %v", tokenHash[:10], errRevoke)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "Error processing token rotation"})
		return
	}
	if !revoked {
		// Isso não deveria acontecer se GetValidRefreshTokenByHash funcionou, mas checar nunca é demais
		log.Printf("AVISO: Refresh token (hash: %s...) não encontrado ou já revogado ao tentar revogar durante refresh.", tokenHash[:10])
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException) // Tratar como inválido
		return
	}

	// 5. Buscar os dados do utilizador
	var user models.User
	userID, _ := strconv.ParseUint(userIDStr, 10, 64) // Converte string para uint64
	if err := database.DB.First(&user, uint(userID)).Error; err != nil {
		log.Printf("Utilizador ID %s (do refresh token) não encontrado no DB: %v", userIDStr, err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}

	if !user.IsActive {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "User is inactive"})
		return
	}

	// 6. Criar NOVOS tokens (access e refresh)
	// Ao refrescar, o MFA não foi verificado nesta interação específica
	newTokenResponse, err := createAndStoreTokens(c, &user, false) // mfaPassed = false
	if err != nil {
		log.Printf("Erro ao criar novos tokens durante refresh para user ID %d: %v", user.ID, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "Error generating new tokens"})
		return
	}

	log.Printf("Refresh token bem-sucedido para user ID %d. Novos tokens emitidos.", user.ID)
	c.JSON(http.StatusOK, newTokenResponse)
}

// EnableMFAStart (porta de /mfa/enable)
// Protegido por AuthMiddleware
func EnableMFAStart(c *gin.Context) {
	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	if currentUser.IsMfaEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MFA is already enabled."})
		return
	}

	// Gerar segredo OTP
	key, err := services.GenerateOTP() // Função de auth_service.go
	if err != nil {
		log.Printf("Erro ao gerar OTP key para %s: %v", currentUser.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not generate OTP secret."})
		return
	}
	otpSecret := key.Secret()

	// Salvar segredo PENDENTE no utilizador
	err = services.SetPendingOTPSecret(currentUser, otpSecret)
	if err != nil {
		// O erro de SetPendingOTPSecret já é informativo (DB error ou already enabled)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// Gerar URI e QR Code
	otpURI := services.GenerateOTPAuthURL(key, currentUser.Email) // Função de auth_service.go
	qrCodeBase64, errQR := services.GenerateQRCodeBase64(otpURI)   // Função de auth_service.go
	if errQR != nil {
		// Logar erro, mas retornar a URI mesmo assim
		log.Printf("Erro ao gerar QR Code para %s: %v", currentUser.Email, errQR)
		qrCodeBase64 = "" // Retornar vazio se falhar
	}

	log.Printf("Iniciada habilitação MFA para %s. Segredo pendente salvo.", currentUser.Email)
	c.JSON(http.StatusOK, schemas.MFAEnableResponse{
		OTPUri:       otpURI,
		QRCodeBase64: qrCodeBase64,
	})
}


// EnableMFAConfirm (porta de /mfa/confirm)
// Protegido por AuthMiddleware
func EnableMFAConfirm(c *gin.Context) {
	var input schemas.MFAConfirmRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	// Chamar o serviço para confirmar
	plainRecoveryCodes, err := services.ConfirmMFAEnable(currentUser, input.OTPCode)
	if err != nil {
		// Erro pode ser "already enabled", "no pending secret", "invalid OTP", ou erro DB/recovery
		statusCode := http.StatusInternalServerError
		if err.Error() == "invalid OTP code" || err.Error() == "MFA is already enabled" || err.Error() == "MFA setup was not initiated (no pending secret)" {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{"detail": err.Error()})
		return
	}

	// Sucesso! Retornar dados do utilizador atualizado e códigos de recuperação
	// Precisamos recarregar o utilizador para garantir que temos o estado mais recente (embora Save() deva atualizar)
	database.DB.First(&currentUser, currentUser.ID) // Recarregar

	c.JSON(http.StatusOK, schemas.MFAConfirmResponse{
		User:          schemas.FormatUserResponse(currentUser),
		RecoveryCodes: plainRecoveryCodes,
	})
}


// DisableMFA (porta de /mfa/disable)
// Protegido por AuthMiddleware
func DisableMFA(c *gin.Context) {
	var input schemas.MFADisableRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	// Chamar o serviço para desabilitar
	err := services.DisableMFA(currentUser, input.OTPCode)
	if err != nil {
		// Erro pode ser "not enabled" ou "invalid OTP"
		statusCode := http.StatusInternalServerError
		if err.Error() == "invalid OTP code" || err.Error() == "MFA is not enabled" {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{"detail": err.Error()})
		return
	}

	// Sucesso! Retornar dados do utilizador atualizado
	database.DB.First(&currentUser, currentUser.ID) // Recarregar
	c.JSON(http.StatusOK, schemas.FormatUserResponse(currentUser))
}

// ResetPassword (porta de reset-password)
func ResetPassword(c *gin.Context) {
	var input schemas.ResetPasswordRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Validar o token e encontrar o utilizador associado
	user, err := services.GetUserByValidResetToken(input.Token)
	if err != nil {
		// O erro de GetUserByValidResetToken já é informativo q.b.
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// 2. Redefinir a senha do utilizador encontrado
	err = services.ResetPassword(user, input.NewPassword)
	if err != nil {
		// O erro de ResetPassword pode ser erro de DB ou processamento
		// Retorna 500 para erro interno, poderia ser 400 se fosse validação de força
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// 3. Retornar os dados do utilizador atualizado (sem senha)
	c.JSON(http.StatusOK, schemas.FormatUserResponse(user))
}

// Helper para criar tokens e salvar no DB
func createAndStoreTokens(c *gin.Context, user *models.User, mfaPassed bool) (schemas.TokenResponse, error) {
	db := database.DB

	// 1. Criar Access Token
	// (Lógica de Scopes omitida para brevidade)
	accessToken, err := services.CreateAccessToken(user, mfaPassed, nil)
	if err != nil {
		return schemas.TokenResponse{}, err
	}

	// 2. Criar Refresh Token
	refreshTokenString, expiresAt, err := services.CreateRefreshToken(user.ID)
	if err != nil {
		return schemas.TokenResponse{}, err
	}

	// 3. Armazenar Refresh Token
	ip, ua := getSessionDetails(c)
	refreshTokenHash := services.HashToken(refreshTokenString)

	dbToken := models.RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		ExpiresAt: expiresAt,
		IPAddress: &ip,
		UserAgent: &ua,
	}

	if err := db.Create(&dbToken).Error; err != nil {
		log.Printf("Erro DB ao criar refresh token para user ID %d: %v", user.ID, err)
		return schemas.TokenResponse{}, err
	}

	return schemas.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		TokenType:    "bearer",
	}, nil
}

// Helper para setar o cookie de device trust
func setTrustedDeviceCookie(c *gin.Context, user *models.User) (string, error) {
	db := database.DB
	cfg := config.AppConfig

	// Gerar token seguro
	plainTokenBytes := make([]byte, 32)
	_, err := rand.Read(plainTokenBytes)
	if err != nil {
		log.Printf("Erro ao gerar bytes aleatórios para device token: %v", err)
		return "", err
	}
	plainToken := hex.EncodeToString(plainTokenBytes) // 64 caracteres hex

	tokenHash := services.HashToken(plainToken)
	ip, ua := getSessionDetails(c)
	now := time.Now().UTC()
	desc := ua // Simplificado por agora

	dbDevice := models.TrustedDevice{
		UserID:          user.ID,
		DeviceTokenHash: tokenHash,
		IPAddress:       &ip,
		UserAgent:       &ua,
		Description:     &desc,
		LastUsedAt:      &now,
	}

	if err := db.Create(&dbDevice).Error; err != nil {
		log.Printf("Erro DB ao criar trusted device para user ID %d: %v", user.ID, err)
		return "", err
	}

	// Determinar Secure baseado no schema (melhor seria verificar X-Forwarded-Proto em produção real)
	isSecure := c.Request.URL.Scheme == "https" || c.Request.Header.Get("X-Forwarded-Proto") == "https"


	c.SetCookie(
		cfg.CookieName,
		plainToken,
		int(cfg.TrustedDeviceCookieMaxAge.Seconds()),
		"/",                      // path
		c.Request.URL.Hostname(), // domain (ajustar se necessário)
		isSecure,                 // secure
		true,                     // httpOnly
	)
	log.Printf("Cookie de dispositivo confiável (ID: %d) definido para user ID %d", dbDevice.ID, user.ID)

	return plainToken, nil
}


// Login (porta de login_for_access_token)
func Login(c *gin.Context) {
	var input schemas.LoginRequest
	// Usar ShouldBind() pois é form-data
	if err := c.ShouldBind(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Autenticar (porta de crud_user.authenticate)
	user, err := services.AuthenticateUser(input.Username, input.Password)
	if err != nil {
		// Verifica se o erro é ErrAccountLocked
		if errors.Is(err, services.ErrAccountLocked) {
			c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()}) // Usa a mensagem formatada do erro
		} else {
			// Outros erros de autenticação (email/senha incorreto, inativo, etc.)
			c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		}
		return
	}


	// 2. Lógica de Device Trust
	isDeviceTrusted := false
	cookie, err := c.Cookie(config.AppConfig.CookieName)
	if err == nil && cookie != "" {
		tokenHash := services.HashToken(cookie)
		var trustedDevice models.TrustedDevice
		// (Porta de crud_trusted_device.get_trusted_device_by_token)
		// Atualiza last_used_at ao verificar
		errDb := database.DB.Where("device_token_hash = ?", tokenHash).First(&trustedDevice).Error
		if errDb == nil && trustedDevice.UserID == user.ID {
				isDeviceTrusted = true
				now := time.Now().UTC()
				database.DB.Model(&trustedDevice).Update("last_used_at", &now) // Atualiza timestamp
				log.Printf("Login para %s: Dispositivo confiável detectado (ID: %d).", user.Email, trustedDevice.ID)
		}
	}

	// 3. Verificar se MFA é necessário
	if user.IsMfaEnabled && !isDeviceTrusted {
		mfaChallengeToken, err := services.CreateMFAChallengeToken(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not create MFA challenge"})
			return
		}

		log.Printf("Login para %s: MFA necessário (dispositivo não confiável), challenge token emitido.", user.Email)
		// Retorna 200 OK com o challenge (como no Python)
		c.JSON(http.StatusOK, schemas.MFARequiredResponse{
			Detail:            "MFA verification required",
			MFAChallengeToken: mfaChallengeToken,
		})
		return
	}

	// 4. Login bem-sucedido (MFA não habilitado ou device confiável)
	log.Printf("Login para %s: Sucesso. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, user, user.IsMfaEnabled) // mfa_passed=true se estava habilitado e foi pulado
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	// Se MFA foi pulado por causa do dispositivo confiável, NÃO precisamos setar novo cookie.
	// Se MFA NUNCA foi habilitado, também não setamos o cookie (ainda).

	c.JSON(http.StatusOK, tokenResponse)
}

// VerifyMFALogin (porta de verify_mfa_login)
func VerifyMFALogin(c *gin.Context) {
	var input schemas.MFAVerifyRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Validar challenge token
	userIDStr, err := services.ValidateMFAChallengeToken(input.MFAChallengeToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired MFA challenge token."})
		return
	}

	// 2. Encontrar utilizador
	var user models.User
	if err := database.DB.First(&user, "id = ?", userIDStr).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid user associated with MFA challenge"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "User is inactive"})
		return
	}
	if !user.IsMfaEnabled || user.OtpSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MFA is not enabled for this user."})
		return
	}

	// 3. Validar OTP
	if !services.ValidateOTP(*user.OtpSecret, input.OTPCode) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid OTP code."})
		return
	}

	// 4. Sucesso! Emitir tokens
	log.Printf("Verificação MFA (OTP) bem-sucedida para %s. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, &user, true) // mfa_passed=true
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	// 5. CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE
	_, errCookie := setTrustedDeviceCookie(c, &user)
	if errCookie != nil {
		// Logar o erro, mas continuar - o login foi bem-sucedido
		log.Printf("AVISO: Falha ao setar cookie de dispositivo confiável para %s após verificação MFA: %v", user.Email, errCookie)
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// VerifyMFARecoveryLogin (porta de verify_mfa_recovery_login)
func VerifyMFARecoveryLogin(c *gin.Context) {
	var input schemas.MFARecoveryRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Validar challenge token
	userIDStr, err := services.ValidateMFAChallengeToken(input.MFAChallengeToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired MFA challenge token."})
		return
	}

	// 2. Encontrar utilizador
	var user models.User
	if err := database.DB.First(&user, "id = ?", userIDStr).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid user associated with MFA challenge"})
		return
	}
	if !user.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "User is inactive"})
		return
	}
	if !user.IsMfaEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MFA is not enabled for this user."})
		return
	}

	// 3. Validar Recovery Code (porta de crud_mfa_recovery_code.get_valid_recovery_code)
	var validCode models.MFARecoveryCode
	foundCode := false

	var codes []models.MFARecoveryCode
	// Buscar códigos não usados para o utilizador
	database.DB.Where("user_id = ? AND is_used = ?", user.ID, false).Find(&codes)

	for _, code := range codes {
		// Comparar hash (reutilizando a função de senha)
		if services.VerifyRecoveryCode(input.RecoveryCode, code.HashedCode) {
			validCode = code
			foundCode = true
			break
		}
	}

	if !foundCode {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or used recovery code."})
		return
	}

	// 4. Marcar como usado
	validCode.IsUsed = true
	if errDb := database.DB.Save(&validCode).Error; errDb != nil {
		log.Printf("Erro DB ao marcar código de recuperação ID %d como usado: %v", validCode.ID, errDb)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error processing recovery code."})
		return
	}

	// 5. Sucesso! Emitir tokens
	log.Printf("Verificação MFA (RECOVERY CODE) bem-sucedida para %s. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, &user, true) // mfa_passed=true
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	// 6. CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE
	_, errCookie := setTrustedDeviceCookie(c, &user)
	if errCookie != nil {
		log.Printf("AVISO: Falha ao setar cookie de dispositivo confiável para %s após uso de recovery code: %v", user.Email, errCookie)
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// GetGoogleLoginURL (porta de get_google_login_url)
func GetGoogleLoginURL(c *gin.Context) {
	cfg := config.AppConfig
	if cfg.GoogleClientID == "" || cfg.GoogleRedirectURI == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Google OAuth not configured on server."})
		return
	}

	conf := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURI, // O redirect é o DO FRONTEND
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// "offline" para refresh token (se necessário), "select_account" para forçar escolha
	url := conf.AuthCodeURL("state-string", oauth2.AccessTypeOffline, oauth2.ApprovalForce) // Usar um state real em produção

	c.JSON(http.StatusOK, schemas.GoogleLoginUrlResponse{URL: url})
}

// GoogleCallback (porta de google_callback)
func GoogleCallback(c *gin.Context) {
	var input schemas.GoogleLoginRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}
	code := input.Code

	cfg := config.AppConfig
	if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" || cfg.GoogleRedirectURI == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Google OAuth not configured on server."})
		return
	}

	conf := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURI, // O redirect esperado aqui é o mesmo usado para gerar a URL
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// 1. Trocar o 'code' por um token do Google
	ctx := c.Request.Context() // Usar o contexto da requisição
	googleToken, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Printf("Erro ao trocar código Google: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired authorization code."})
		return
	}

	if !googleToken.Valid() {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid token received from Google."})
		return
	}

	// 2. Obter informações do utilizador da Google
	client := conf.Client(ctx, googleToken)
	userInfoResp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Printf("Erro ao buscar userinfo do Google: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to fetch user info from Google."})
		return
	}
	defer userInfoResp.Body.Close()

	if userInfoResp.StatusCode != http.StatusOK {
		log.Printf("Erro do Google UserInfo API: Status %d", userInfoResp.StatusCode)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to fetch user info from Google."})
		return
	}

	var userInfo struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		// Adicionar outros campos se necessário (ex: picture, sub)
	}
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
		log.Printf("Erro ao decodificar resposta userinfo do Google: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to process user info from Google."})
		return
	}

	if userInfo.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Email not returned by Google."})
		return
	}
	if !userInfo.EmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Google email is not verified."})
		return
	}

	// 3. Encontrar ou Criar o utilizador na nossa BD
	user, err := services.GetOrCreateByEmailOAuth(userInfo.Email, userInfo.Name)
	if err != nil {
		log.Printf("Erro ao buscar/criar utilizador OAuth na BD para %s: %v", userInfo.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal error processing account."})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Account is deactivated."})
		return
	}

	// 4. Emitir os NOSSOS tokens JWT
	log.Printf("Login OAuth bem-sucedido para %s. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, user, true) // Login social é considerado como MFA passado
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating API tokens"})
		return
	}

	// 5. CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE
	_, errCookie := setTrustedDeviceCookie(c, user)
	if errCookie != nil {
		log.Printf("AVISO: Falha ao setar cookie de dispositivo confiável para %s após login Google: %v", user.Email, errCookie)
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// Logout (porta de logout)
func Logout(c *gin.Context) {
	var input schemas.RefreshTokenRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		// Se não vier corpo, tenta revogar o cookie de device trust (melhor esforço)
		log.Printf("Logout chamado sem refresh token no corpo. Apenas limpando cookie.")
		c.SetCookie(config.AppConfig.CookieName, "", -1, "/", c.Request.URL.Hostname(), true, true)
		c.Status(http.StatusNoContent)
		return
		// Se quiser exigir o token:
		// c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		// return
	}

	// Revogar o refresh token fornecido
	tokenHash := services.HashToken(input.RefreshToken)
	result := database.DB.Model(&models.RefreshToken{}).Where("token_hash = ?", tokenHash).Update("is_revoked", true)

	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.Printf("Erro DB ao revogar refresh token: %v", result.Error)
		// Continua mesmo assim para limpar o cookie
	}
	if result.RowsAffected > 0 {
		log.Printf("Refresh token (hash: %s...) revogado durante logout.", tokenHash[:10])
	}

	// Apagar cookie de dispositivo confiável
	// Determinar Secure baseado no schema
	isSecure := c.Request.URL.Scheme == "https" || c.Request.Header.Get("X-Forwarded-Proto") == "https"
	c.SetCookie(
		config.AppConfig.CookieName,
		"",                       // Valor vazio
		-1,                       // MaxAge < 0 para expirar imediatamente
		"/",                      // Path
		c.Request.URL.Hostname(), // Domain
		isSecure,                 // Secure
		true,                     // HttpOnly
	)
	log.Println("Cookie de dispositivo confiável removido durante logout.")


	c.Status(http.StatusNoContent)
}


// VerifyEmail (porta de verify-email/{token})
func VerifyEmail(c *gin.Context) {
	token := c.Param("token") // Pega o token do path da URL
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Verification token is missing"})
		return
	}

	tokenHash := services.HashToken(token)
	now := time.Now().UTC()
	db := database.DB
	var user models.User

	// Encontrar utilizador pelo hash do token, verificando expiração e status
	err := db.Where("verification_token_hash = ? AND verification_token_expires > ? AND is_verified = ?", tokenHash, now, false).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired verification token"})
			return
		}
		log.Printf("Erro DB ao procurar token de verificação: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error processing verification"})
		return
	}

	// Utilizador encontrado e token válido, atualizar utilizador
	user.IsActive = true
	user.IsVerified = true
	user.VerificationTokenHash = nil    // Limpar token
	user.VerificationTokenExpires = nil // Limpar expiração

	if err := db.Save(&user).Error; err != nil {
		log.Printf("Erro ao salvar utilizador após verificação: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not finalize verification"})
		return
	}

	log.Printf("Email verificado com sucesso para utilizador ID: %d (%s)", user.ID, user.Email)
	c.JSON(http.StatusOK, schemas.FormatUserResponse(&user))
}