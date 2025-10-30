# ---- 1. Build Stage ----
# Usar uma imagem oficial do Go mais recente
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Instalar a ferramenta swag
RUN go install github.com/swaggo/swag/cmd/swag@latest

# Copia TODO o conteúdo da pasta go-auth-api (do contexto de build) para o WORKDIR /app
COPY go-auth-api/ ./

# Baixar as dependências externas
RUN go mod download

# GERAR DOCUMENTAÇÃO SWAGGER
RUN swag init -g cmd/api/main.go

# Compilar o binário
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/main ./cmd/api/

# ---- 2. Final Stage ----
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/.env .env

EXPOSE 8001
CMD ["./main"]