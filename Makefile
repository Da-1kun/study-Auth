.PHONY: run test

# .env を環境変数として読み込んでから起動する（godotenv 等を使ってもよい）
run:
	@set -a; [ -f .env ] && . ./.env; set +a; go run .

test:
	go test ./...
