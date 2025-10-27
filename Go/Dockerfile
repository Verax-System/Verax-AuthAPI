# ---- 1. Build Stage ----
# Usar a imagem oficial do Go como builder
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copiar os arquivos de dependência e baixá-las
COPY go.mod go.sum ./
RUN go mod download

# Copiar o restante do código-fonte
COPY . .

# Build o binário estático para Linux
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/main ./cmd/api/

# ---- 2. Final Stage ----
# Usar uma imagem base mínima
FROM alpine:latest

WORKDIR /app

# Copiar apenas o binário compilado do 'builder'
COPY --from=builder /app/main .

# Copiar o .env para a imagem final
# Em produção, você injetaria isso via segredos do Docker/K8s
COPY .env .

# Expor a porta que o Gin irá escutar
EXPOSE 8001

# Comando para rodar a aplicação
CMD ["./main"]